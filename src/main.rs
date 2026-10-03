//! enum4all — a native, cross-platform Rust port of enum4linux.

mod cli;
mod netbios;
mod output;
mod rprn_ext;
mod samr_ext;
mod smb;
mod srvsvc_ext;

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
    let host = smb::bare_host(&args.target);
    match netbios::node_status(&host, args.nbt_port, args.timeout).await {
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
    let need_session = args.shares
        || args.users
        || args.groups
        || args.pass_pol
        || args.rid_cycle
        || args.os
        || args.printers;
    if !need_session {
        return;
    }

    let mut session = match SmbSession::open(
        &args.target,
        &args.user,
        &args.pass,
        &args.workgroup,
        args.timeout,
    )
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

    // OS enrichment via NetrServerGetInfo (merges into the probe's OsInfo).
    if args.os {
        match session.server_info().await {
            Ok(si) => {
                if !args.json {
                    output::section("Server Info (SRVSVC)");
                    if let Some(os) = &si.server_os {
                        output::good(format!("Server OS ......... {os}"));
                    }
                    if let Some(cn) = &si.computer_name {
                        output::good(format!("Computer name ..... {cn}"));
                    }
                }
                let entry = report.os_info.get_or_insert_with(Default::default);
                if si.server_os.is_some() {
                    entry.server_os = si.server_os;
                }
                if si.server_version.is_some() {
                    entry.server_version = si.server_version;
                }
                if si.computer_name.is_some() {
                    entry.computer_name = si.computer_name;
                }
            }
            Err(e) => report.note_error("server_info", e.to_string()),
        }
    }

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
                        let access = sh
                            .access
                            .as_deref()
                            .map(|a| format!(" [{a}]"))
                            .unwrap_or_default();
                        let comment = sh
                            .comment
                            .as_deref()
                            .map(|c| format!(" - {c}"))
                            .unwrap_or_default();
                        output::good(format!(
                            "{:<20} ({}){comment}{access}",
                            sh.name, sh.share_type
                        ));
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
        if let Ok(sessions) = session.sessions().await
            && !args.json
            && !sessions.is_empty()
        {
            output::section("Active Sessions (SRVSVC)");
            for (client, user) in &sessions {
                output::good(format!("{user} @ {client}"));
            }
        }
        if let Ok(logged) = session.logged_on_users().await
            && !args.json
            && !logged.is_empty()
        {
            output::section("Logged-on Users (WKSSVC)");
            for (user, domain) in &logged {
                output::good(format!("{domain}\\{user}"));
            }
        }
    }

    // Groups + aliases (SAMR) ---------------------------------------------
    if args.groups {
        if !args.json {
            output::section("Groups & Aliases (SAMR)");
        }
        match session.groups().await {
            Ok(groups) => {
                if !args.json {
                    if groups.is_empty() {
                        output::warn("No groups returned");
                    }
                    for g in &groups {
                        output::good(format!("rid {:<6} [{}] {}", g.rid, g.group_type, g.name));
                        for m in &g.members {
                            println!("        └─ {m}");
                        }
                    }
                }
                report.groups = groups;
            }
            Err(e) => {
                if !args.json {
                    output::error(format!("Group enumeration failed: {e}"));
                }
                report.note_error("groups", e.to_string());
            }
        }
    }

    // Printers (spoolss) ---------------------------------------------------
    if args.printers {
        if !args.json {
            output::section("Printers (spoolss)");
        }
        match session.printers().await {
            Ok(printers) => {
                if !args.json {
                    if printers.is_empty() {
                        output::warn("No printers returned");
                    }
                    for p in &printers {
                        let c = if p.comment.is_empty() {
                            String::new()
                        } else {
                            format!(" - {}", p.comment)
                        };
                        output::good(format!("{}{c}", p.name));
                    }
                }
                report.printers = printers;
            }
            Err(e) => {
                if !args.json {
                    output::error(format!("Printer enumeration failed: {e}"));
                }
                report.note_error("printers", e.to_string());
            }
        }
    }

    // Password policy (SAMR) ----------------------------------------------
    if args.pass_pol {
        if !args.json {
            output::section("Password Policy (SAMR)");
        }
        match session.password_policy().await {
            Ok(pol) => {
                if !args.json {
                    if let Some(v) = pol.min_length {
                        output::good(format!("Minimum password length ... {v}"));
                    }
                    if let Some(v) = pol.history_length {
                        output::good(format!("Password history length .... {v}"));
                    }
                    match pol.max_age_days {
                        Some(v) => output::good(format!("Maximum password age ....... {v} days")),
                        None => output::good("Maximum password age ....... never"),
                    }
                    match pol.min_age_days {
                        Some(v) => output::good(format!("Minimum password age ....... {v} days")),
                        None => output::good("Minimum password age ....... none"),
                    }
                    if let Some(v) = pol.complexity {
                        output::good(format!("Complexity required ........ {v}"));
                    }
                    if let Some(v) = pol.lockout_threshold {
                        let s = if v == 0 {
                            "disabled".to_string()
                        } else {
                            v.to_string()
                        };
                        output::good(format!("Account lockout threshold .. {s}"));
                    }
                }
                report.password_policy = Some(pol);
            }
            Err(e) => {
                if !args.json {
                    output::error(format!("Password policy query failed: {e}"));
                }
                report.note_error("password_policy", e.to_string());
            }
        }
    }

    // RID cycling (SAMR LookupIdsInDomain) --------------------------------
    if args.rid_cycle {
        if !args.json {
            output::section("RID Cycling (SAMR)");
        }
        match cli::parse_rid_ranges(&args.rid_range) {
            Ok(rids) => match session.rid_cycle(&rids).await {
                Ok((domain_sid, accounts)) => {
                    if !args.json {
                        output::info(format!("Domain SID: {domain_sid}"));
                        if accounts.is_empty() {
                            output::warn("No RIDs resolved in the given range");
                        }
                        for a in &accounts {
                            let kind = a.description.as_deref().unwrap_or("");
                            output::good(format!("rid {:<6} [{kind}] {}", a.rid, a.name));
                        }
                    }
                    // Merge resolved accounts into the users list.
                    report.users.extend(accounts);
                }
                Err(e) => {
                    if !args.json {
                        output::error(format!("RID cycling failed: {e}"));
                    }
                    report.note_error("rid_cycle", e.to_string());
                }
            },
            Err(e) => {
                if !args.json {
                    output::error(format!("Invalid RID range: {e}"));
                }
                report.note_error("rid_cycle", e.to_string());
            }
        }
    }
}

fn print_banner(args: &Cli) {
    println!(
        "enum4all v{} — native SMB/NetBIOS enumeration",
        env!("CARGO_PKG_VERSION")
    );
    println!("Target .......... {}", args.target);
    println!(
        "Credentials ..... {}",
        if args.is_null_session() {
            "null session (anonymous)".to_string()
        } else {
            format!(
                "{}\\{}",
                if args.workgroup.is_empty() {
                    "."
                } else {
                    &args.workgroup
                },
                args.user
            )
        }
    );
}
