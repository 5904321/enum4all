//! enum4mac — a native macOS/Rust port of enum4linux.

mod cli;
mod netbios;
mod output;
mod smb;

use clap::Parser;
use cli::Cli;
use output::Report;
use smb::SmbSession;

#[tokio::main]
async fn main() {
    let args = Cli::parse().resolved();
    let code = run(args).await;
    std::process::exit(code);
}

async fn run(args: Cli) -> i32 {
    if !args.json {
        print_banner(&args);
    }

    let mut report = Report::new(&args.target);
    report.null_session = Some(args.is_null_session());

    run_netbios(&args, &mut report).await;
    run_os(&args, &mut report).await;
    run_smb_rpc(&args, &mut report).await;
    report_unsupported(&args, &mut report);

    if args.json {
        println!("{}", report.to_json());
    } else {
        output::section("Done");
        output::info(format!("Enumeration of {} complete", args.target));
    }

    let produced_anything = !report.netbios.is_empty()
        || report.os_info.is_some()
        || !report.shares.is_empty()
        || !report.users.is_empty()
        || !report.groups.is_empty();
    if produced_anything { 0 } else { 1 }
}

/// NetBIOS node status (UDP/137).
async fn run_netbios(args: &Cli, report: &mut Report) {
    if !args.netbios {
        return;
    }
    if !args.json {
        output::section("NetBIOS Name Service");
    }
    match netbios::node_status(&args.target, args.timeout).await {
        Ok(status) => {
            if let Some(wg) = &status.workgroup {
                report.workgroup = Some(wg.clone());
            }
            if !args.json {
                if status.names.is_empty() {
                    output::warn("No NetBIOS names returned");
                } else {
                    for n in &status.names {
                        output::good(format!(
                            "{:<36} <{:02x}>  {:<7} {}",
                            n.name, n.suffix, n.kind, n.flags
                        ));
                    }
                }
                if let Some(mac) = &status.mac {
                    output::good(format!("MAC Address: {mac}"));
                }
                if let Some(wg) = &status.workgroup {
                    output::good(format!("Workgroup/Domain: {wg}"));
                }
            }
            report.netbios = status.names;
        }
        Err(e) => {
            if !args.json {
                output::error(format!("NetBIOS query failed: {e}"));
            }
            report.note_error("netbios", e.to_string());
        }
    }
}

/// OS / dialect / signing info from an unauthenticated NEGOTIATE probe.
async fn run_os(args: &Cli, report: &mut Report) {
    if !args.os {
        return;
    }
    if !args.json {
        output::section("OS Information");
    }
    match SmbSession::probe_os(&args.target, args.timeout).await {
        Ok(mut os) => {
            if let Some(wg) = &report.workgroup {
                os.domain.get_or_insert(wg.clone());
            }
            if !args.json {
                if let Some(d) = &os.dialect {
                    output::good(format!("SMB dialect ....... {d}"));
                }
                if let Some(s) = &os.signing {
                    output::good(format!("Message signing ... {s}"));
                }
                if let Some(dom) = &os.domain {
                    output::good(format!("Domain/Workgroup .. {dom}"));
                }
            }
            report.os_info = Some(os);
        }
        Err(e) => {
            if !args.json {
                output::error(format!("OS probe failed: {e}"));
            }
            report.note_error("os", e.to_string());
        }
    }
}

/// Authenticated/null-session MSRPC enumeration: shares, users, sessions.
async fn run_smb_rpc(args: &Cli, report: &mut Report) {
    let need_session = args.shares || args.users;
    if !need_session {
        return;
    }

    let mut session =
        match SmbSession::open(&args.target, &args.user, &args.pass, &args.workgroup, args.timeout)
            .await
        {
            Ok(s) => {
                if !args.json {
                    output::section("SMB Session");
                    output::good(if s.null_session {
                        "Null session established (anonymous IPC$ access)"
                    } else {
                        "Authenticated session established"
                    });
                }
                s
            }
            Err(e) => {
                if !args.json {
                    output::section("SMB Session");
                    output::error(format!("Could not establish SMB session: {e}"));
                    output::info("Skipping share/user enumeration (needs a usable session).");
                }
                report.note_error("smb_session", e.to_string());
                return;
            }
        };

    // Shares (SRVSVC) ------------------------------------------------------
    if args.shares {
        if !args.json {
            output::section("Shares (SRVSVC)");
        }
        match session.shares().await {
            Ok(mut shares) => {
                if args.detail {
                    for sh in &mut shares {
                        sh.access = Some(session.test_share_access(&sh.name).await);
                    }
                }
                if !args.json {
                    if shares.is_empty() {
                        output::warn("No shares returned");
                    }
                    for sh in &shares {
                        let access = sh.access.as_deref().map(|a| format!(" [{a}]")).unwrap_or_default();
                        let comment = sh.comment.as_deref().map(|c| format!(" - {c}")).unwrap_or_default();
                        output::good(format!("{:<20} ({}){comment}{access}", sh.name, sh.share_type));
                    }
                }
                report.shares = shares;
            }
            Err(e) => {
                if !args.json {
                    output::error(format!("Share enumeration failed: {e}"));
                }
                report.note_error("shares", e.to_string());
            }
        }
    }

    // Users (SAMR) ---------------------------------------------------------
    if args.users {
        if !args.json {
            output::section("Users (SAMR)");
        }
        match session.users().await {
            Ok(users) => {
                if !args.json {
                    if users.is_empty() {
                        output::warn("No users returned");
                    }
                    for u in &users {
                        output::good(format!("rid {:<6} {}", u.rid, u.name));
                    }
                }
                report.users = users;
            }
            Err(e) => {
                if !args.json {
                    output::error(format!("User enumeration failed: {e}"));
                }
                report.note_error("users", e.to_string());
            }
        }

        // Bonus: active sessions + logged-on users (cheap, same session).
        if let Ok(sessions) = session.sessions().await {
            if !args.json && !sessions.is_empty() {
                output::section("Active Sessions (SRVSVC)");
                for (client, user) in &sessions {
                    output::good(format!("{user} @ {client}"));
                }
            }
        }
        if let Ok(logged) = session.logged_on_users().await {
            if !args.json && !logged.is_empty() {
                output::section("Logged-on Users (WKSSVC)");
                for (user, domain) in &logged {
                    output::good(format!("{domain}\\{user}"));
                }
            }
        }
    }
}

/// Sections not yet implemented (Phase 3b: groups, password policy, RID cycling).
fn report_unsupported(args: &Cli, report: &mut Report) {
    let mut pending = Vec::new();
    if args.groups {
        pending.push("groups (-G)");
    }
    if args.pass_pol {
        pending.push("password policy (-P)");
    }
    if args.rid_cycle {
        pending.push("RID cycling (-r)");
    }
    if pending.is_empty() {
        return;
    }
    if !args.json {
        output::section("Not Yet Implemented");
        for p in &pending {
            output::warn(format!("{p} — planned for Phase 3b (raw SAMR/LSA opnums)"));
        }
    }
    report.note_error("unimplemented", pending.join(", "));
}

fn print_banner(args: &Cli) {
    println!("enum4mac v{} — native SMB/NetBIOS enumeration", env!("CARGO_PKG_VERSION"));
    println!("Target .......... {}", args.target);
    println!(
        "Credentials ..... {}",
        if args.is_null_session() {
            "null session (anonymous)".to_string()
        } else {
            format!(
                "{}\\{}",
                if args.workgroup.is_empty() { "." } else { &args.workgroup },
                args.user
            )
        }
    );
}
