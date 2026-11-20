mod crypto;
mod discord;

use crypto::{
    decrypt_message, decrypt_stream, derive_context_key, derive_user_key, encrypt_message,
    encrypt_stream, forced_channel_password, looks_encrypted, max_plaintext_bytes, MasterKey,
    Preset,
};
use discord::{DiscordClient, DiscordMessage};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[derive(Clone)]
struct CachedAttachment {
    channel_id: String,
    author_id: String,
    filename: String,
    url: String,
}

struct Session {
    key: Arc<RwLock<Arc<MasterKey>>>,
    key_label: String,
    preset: Preset,
    channel_id: String,
    sender_id: String,
    discord: Option<Arc<DiscordClient>>,
    attachments: Arc<Mutex<Vec<CachedAttachment>>>,
}

impl Session {
    fn current_key(&self) -> Arc<MasterKey> {
        Arc::clone(&self.key.read().unwrap())
    }

    fn replace_key(&mut self, new_key: MasterKey, label: String) {
        let mut guard = self.key.write().unwrap();
        *guard = Arc::new(new_key);
        self.key_label = label;
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut channel_id = String::from("0");
    let mut sender_id = String::from("0");
    let mut preset = Preset::Aes256;
    let mut context: Option<String> = None;
    let mut auto_login = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_cli_usage();
                return;
            }
            "-c" | "--channel" if i + 1 < args.len() => {
                channel_id = args[i + 1].clone();
                i += 2;
            }
            "-s" | "--sender" if i + 1 < args.len() => {
                sender_id = args[i + 1].clone();
                i += 2;
            }
            "-p" | "--preset" if i + 1 < args.len() => {
                match Preset::parse(&args[i + 1]) {
                    Some(p) => preset = p,
                    None => {
                        eprintln!("Invalid preset '{}'. Use: aes128, aes192, or aes256.", args[i + 1]);
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            "--ctx" | "--context" if i + 1 < args.len() => {
                context = Some(args[i + 1].clone());
                i += 2;
            }
            "--login" => {
                auto_login = true;
                i += 1;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                print_cli_usage();
                std::process::exit(1);
            }
        }
    }

    println!("Aegires-gen3 CLI (dcenc2) — Pure Rust Cross-Platform E2EE");
    println!("Keys & Discord tokens stay in RAM only and are wiped on exit.\n");

    let (key, key_label) = match prompt_and_derive(context.as_deref()) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let mut session = Session {
        key: Arc::new(RwLock::new(Arc::new(key))),
        key_label,
        preset,
        channel_id,
        sender_id,
        discord: None,
        attachments: Arc::new(Mutex::new(Vec::new())),
    };

    if auto_login {
        handle_login(&mut session);
    }

    println!(
        "Session unlocked [{}] | Preset: {} | Channel: {} | Sender: {}",
        session.key_label,
        session.preset.label(),
        session.channel_id,
        session.sender_id
    );
    println!("Tip: Run 'login' to auto-detect Discord IDs & decrypt anyone's messages, or 'help' for all commands.\n");

    run_repl(&mut session);
    println!("Master key and session secrets wiped from memory. Goodbye.");
}

fn prompt_and_derive(context: Option<&str>) -> Result<(MasterKey, String), String> {
    let prompt = match context {
        Some(ctx) => format!("Argon2id passphrase (ctx='{ctx}'): "),
        None => "Argon2id passphrase: ".to_string(),
    };
    let mut pw = rpassword::prompt_password(prompt)
        .map_err(|e| format!("Could not read passphrase: {e}"))?;
    if pw.is_empty() {
        pw.zeroize();
        return Err("Passphrase cannot be empty".into());
    }

    print!("Deriving 256-bit key (Argon2id 64 MiB, 3 passes)...");
    let _ = io::stdout().flush();
    let start = Instant::now();

    let key_res = match context {
        Some(ctx) => derive_context_key(&pw, ctx),
        None => derive_user_key(&pw),
    };
    pw.zeroize();

    let key = key_res?;
    println!(" done in {:.0} ms.", start.elapsed().as_secs_f64() * 1000.0);

    let label = match context {
        Some(ctx) => format!("ctx:{ctx}"),
        None => "user-key".to_string(),
    };
    Ok((key, label))
}

fn run_repl(session: &mut Session) {
    let stdin = io::stdin();
    let mut line = String::new();

    loop {
        let prompt_tag = match &session.discord {
            Some(dc) => format!("{}@{}", dc.me.username, session.channel_id),
            None => session.preset.label().to_string(),
        };
        print!("aegires[{prompt_tag}]> ");
        let _ = io::stdout().flush();

        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) => {
                println!();
                break;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Input error: {e}");
                break;
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Direct paste support: §ciphertext auto-decrypts without typing 'd'.
        if looks_encrypted(trimmed) {
            handle_decrypt_text(session, trimmed);
            continue;
        }

        // Direct paste support: Discord message/channel URLs auto-fetch & decrypt.
        if let Some((ch_id, msg_id_opt)) = parse_discord_link(trimmed) {
            handle_discord_link(session, &ch_id, msg_id_opt.as_deref());
            continue;
        }

        let (cmd, rest) = split_first_word(trimmed);
        match cmd.to_ascii_lowercase().as_str() {
            "login" => handle_login(session),
            "logout" => handle_logout(session),
            "dms" => handle_dms(session),
            "guilds" | "servers" => handle_guilds(session),
            "channels" | "ch" => handle_channels(session, rest),
            "open" | "use" => handle_open_channel(session, rest),
            "r" | "read" => handle_read_messages(session, rest),
            "s" | "send" => handle_send_message(session, rest),
            "sf" | "sendfile" => handle_send_file(session, rest),
            "dl" | "download" => handle_download_attachment(session, rest),
            "chat" | "watch" => handle_chat_mode(session),
            "e" | "enc" | "encrypt" => handle_encrypt_text(session, rest),
            "d" | "dec" | "decrypt" => handle_decrypt_text(session, rest),
            "ef" | "encfile" => handle_encrypt_file(session, rest),
            "df" | "decfile" => handle_decrypt_file(session, rest),
            "key" | "rekey" => handle_switch_key(session, rest),
            "forced" => handle_forced_channel(session, rest),
            "set" => handle_set(session, rest),
            "status" | "info" => handle_status(session),
            "help" | "?" => print_repl_help(),
            "exit" | "quit" | "q" => break,
            other => eprintln!(
                "Unknown command '{other}'. Type 'e <msg>' to encrypt, 's <msg>' to send, 'chat' for live mode, or 'help'."
            ),
        }
    }
}

// ------------------------------------------------------------ Discord actions

fn handle_login(session: &mut Session) {
    let token = match rpassword::prompt_password("Discord token (hidden input): ") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Could not read token: {e}");
            return;
        }
    };
    print!("Verifying token with Discord...");
    let _ = io::stdout().flush();

    match DiscordClient::login(token) {
        Ok(client) => {
            session.sender_id = client.me.id.clone();
            println!(
                " logged in as {} (@{}, ID: {})",
                client.me.display_name(),
                client.me.username,
                client.me.id
            );
            println!("Sender ID auto-set to {}. Run 'dms' or 'guilds' to pick a channel.", session.sender_id);
            session.discord = Some(Arc::new(client));
        }
        Err(e) => eprintln!("\nLogin failed: {e}"),
    }
}

fn handle_logout(session: &mut Session) {
    if session.discord.take().is_some() {
        println!("Logged out and wiped Discord token from RAM.");
    } else {
        println!("Not logged into Discord.");
    }
}

fn require_discord(session: &Session) -> Option<Arc<DiscordClient>> {
    match &session.discord {
        Some(dc) => Some(Arc::clone(dc)),
        None => {
            eprintln!("Not logged in. Run 'login' first.");
            None
        }
    }
}

fn handle_dms(session: &Session) {
    let Some(dc) = require_discord(session) else {
        return;
    };
    match dc.list_dms() {
        Ok(dms) => {
            if dms.is_empty() {
                println!("No DMs found.");
                return;
            }
            println!("DMs (use `open <channel_id>`):");
            for dm in dms.iter().take(25) {
                println!("  {}  {}", dm.id, dm.display_label());
            }
        }
        Err(e) => eprintln!("Failed to fetch DMs: {e}"),
    }
}

fn handle_guilds(session: &Session) {
    let Some(dc) = require_discord(session) else {
        return;
    };
    match dc.list_guilds() {
        Ok(guilds) => {
            if guilds.is_empty() {
                println!("No servers found.");
                return;
            }
            println!("Servers (use `channels <guild_id>`):");
            for g in guilds {
                println!("  {}  {}", g.id, g.name);
            }
        }
        Err(e) => eprintln!("Failed to fetch servers: {e}"),
    }
}

fn handle_channels(session: &Session, rest: &str) {
    let Some(dc) = require_discord(session) else {
        return;
    };
    let guild_id = rest.trim();
    if guild_id.is_empty() {
        eprintln!("Usage: channels <guild_id>");
        return;
    }
    match dc.list_guild_channels(guild_id) {
        Ok(channels) => {
            println!("Text channels (use `open <channel_id>`):");
            for ch in channels {
                // 0 = GuildText, 5 = Announcement, 10/11/12 = Threads
                if matches!(ch.kind, 0 | 5 | 10 | 11 | 12) {
                    println!("  {}  {}", ch.id, ch.display_label());
                }
            }
        }
        Err(e) => eprintln!("Failed to fetch channels: {e}"),
    }
}

fn handle_open_channel(session: &mut Session, rest: &str) {
    let target = rest.trim();
    if target.is_empty() {
        eprintln!("Usage: open <channel_id or discord_link>");
        return;
    }

    let ch_id = if let Some((ch, msg_opt)) = parse_discord_link(target) {
        if let Some(msg_id) = msg_opt {
            handle_discord_link(session, &ch, Some(&msg_id));
            return;
        }
        ch
    } else {
        target.to_string()
    };

    session.channel_id = ch_id.clone();
    println!("Active channel -> {ch_id}");

    if forced_channel_password(&ch_id).is_some() {
        println!("Note: This channel has a built-in forced key. Run 'forced {ch_id}' to load it.");
    }

    if session.discord.is_some() {
        handle_read_messages(session, "10");
    }
}

fn handle_discord_link(session: &mut Session, ch_id: &str, msg_id: Option<&str>) {
    session.channel_id = ch_id.to_string();
    let Some(dc) = require_discord(session) else {
        println!("Channel ID set to {ch_id} (login to auto-fetch message & author ID).");
        return;
    };

    match msg_id {
        Some(mid) => match dc.get_message_by_id(ch_id, mid) {
            Ok(msg) => {
                let key = session.current_key();
                render_message(&msg, &key, &session.attachments);
            }
            Err(e) => eprintln!("Could not fetch linked message: {e}"),
        },
        None => {
            println!("Active channel -> {ch_id}");
            handle_read_messages(session, "10");
        }
    }
}

fn handle_read_messages(session: &Session, rest: &str) {
    let Some(dc) = require_discord(session) else {
        return;
    };
    if session.channel_id == "0" {
        eprintln!("No channel selected. Run 'open <channel_id>' (or 'dms' / 'guilds') first.");
        return;
    }
    let limit = rest.trim().parse::<usize>().unwrap_or(15).clamp(1, 50);

    match dc.get_messages(&session.channel_id, limit) {
        Ok(mut msgs) => {
            msgs.reverse(); // Display oldest -> newest.
            if msgs.is_empty() {
                println!("(No messages in channel)");
                return;
            }
            let key = session.current_key();
            for m in &msgs {
                render_message(m, &key, &session.attachments);
            }
        }
        Err(e) => eprintln!("Failed to read messages: {e}"),
    }
}

fn handle_send_message(session: &Session, rest: &str) {
    let Some(dc) = require_discord(session) else {
        return;
    };
    if session.channel_id == "0" {
        eprintln!("No channel selected. Run 'open <channel_id>' first.");
        return;
    }
    let text = rest.trim();
    if text.is_empty() {
        eprintln!("Usage: s <message>");
        return;
    }
    let key = session.current_key();
    match encrypt_message(text, &key, session.preset, &session.channel_id, &dc.me.id) {
        Ok(wire) => match dc.send_message(&session.channel_id, &wire) {
            Ok(sent) => println!("Sent [{} | id:{}]", session.preset.label(), sent.id),
            Err(e) => eprintln!("Send failed: {e}"),
        },
        Err(e) => eprintln!("Encrypt error: {e}"),
    }
}

fn handle_send_file(session: &Session, rest: &str) {
    let Some(dc) = require_discord(session) else {
        return;
    };
    if session.channel_id == "0" {
        eprintln!("No channel selected. Run 'open <channel_id>' first.");
        return;
    }

    let tokens = match split_shell_args(rest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Argument parse error: {e}");
            return;
        }
    };
    if tokens.is_empty() {
        eprintln!("Usage: sendfile <file_path> [optional caption]");
        return;
    }

    let in_path = PathBuf::from(&tokens[0]);
    let caption_plain = if tokens.len() > 1 {
        Some(tokens[1..].join(" "))
    } else {
        None
    };

    let in_file = match File::open(&in_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open '{}': {e}", in_path.display());
            return;
        }
    };

    let key = session.current_key();
    let mut reader = BufReader::new(in_file);
    let mut enc_buf: Vec<u8> = Vec::new();

    print!("Encrypting '{}'...", in_path.display());
    let _ = io::stdout().flush();

    let bytes = match encrypt_stream(
        &mut reader,
        &mut enc_buf,
        &key,
        session.preset,
        &session.channel_id,
        &dc.me.id,
    ) {
        Ok(b) => b,
        Err(e) => {
            enc_buf.zeroize();
            eprintln!("\nFile encryption failed: {e}");
            return;
        }
    };

    let enc_caption = match caption_plain {
        Some(ref c) => match encrypt_message(c, &key, session.preset, &session.channel_id, &dc.me.id) {
            Ok(w) => Some(w),
            Err(e) => {
                enc_buf.zeroize();
                eprintln!("\nCaption encryption failed: {e}");
                return;
            }
        },
        None => None,
    };

    let base_name = in_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment.bin");
    let upload_name = if base_name.ends_with(".aeg") {
        base_name.to_string()
    } else {
        format!("{base_name}.aeg")
    };

    print!(" uploading {}...", fmt_bytes(enc_buf.len() as u64));
    let _ = io::stdout().flush();

    let upload_res = dc.send_file(
        &session.channel_id,
        &upload_name,
        &enc_buf,
        enc_caption.as_deref(),
    );
    enc_buf.zeroize();

    match upload_res {
        Ok(sent) => println!(
            " done! Sent {} ({}) as '{}' (msg id:{})",
            fmt_bytes(bytes),
            session.preset.label(),
            upload_name,
            sent.id
        ),
        Err(e) => eprintln!("\nUpload failed: {e}"),
    }
}

fn handle_download_attachment(session: &Session, rest: &str) {
    let Some(dc) = require_discord(session) else {
        return;
    };
    let tokens = match split_shell_args(rest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Argument parse error: {e}");
            return;
        }
    };
    if tokens.is_empty() || tokens.len() > 2 {
        eprintln!("Usage: dl <attachment_number> [output_path]");
        return;
    }

    let idx: usize = match tokens[0].trim_start_matches('#').parse::<usize>() {
        Ok(n) if n >= 1 => n - 1,
        _ => {
            eprintln!("Invalid attachment number '{}'. Run 'r' first to see #numbers.", tokens[0]);
            return;
        }
    };

    let cached = {
        let list = session.attachments.lock().unwrap();
        list.get(idx).cloned()
    };

    let Some(att) = cached else {
        eprintln!("Attachment #{} not found. Run 'r' to refresh attachments.", idx + 1);
        return;
    };

    let out_path = if tokens.len() == 2 {
        PathBuf::from(&tokens[1])
    } else {
        let stripped = att.filename.strip_suffix(".aeg").unwrap_or(&att.filename);
        PathBuf::from(format!("decrypted_{stripped}"))
    };

    print!("Downloading & decrypting '{}'...", att.filename);
    let _ = io::stdout().flush();

    let mut reader = match dc.download_reader(&att.url) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("\nDownload failed: {e}");
            return;
        }
    };

    let out_file = match File::create(&out_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("\nCannot create '{}': {e}", out_path.display());
            return;
        }
    };

    let mut writer = BufWriter::new(out_file);
    let key = session.current_key();
    let start = Instant::now();

    match decrypt_stream(&mut reader, &mut writer, &key, &att.channel_id, &att.author_id) {
        Ok((bytes, preset)) => println!(
            " done! Saved {} ({}) -> '{}' in {:.2}s",
            fmt_bytes(bytes),
            preset.label(),
            out_path.display(),
            start.elapsed().as_secs_f64()
        ),
        Err(e) => {
            drop(writer);
            let _ = fs::remove_file(&out_path);
            eprintln!("\nDecryption failed (wrong key or unencrypted file): {e}");
        }
    }
}

fn handle_chat_mode(session: &mut Session) {
    let Some(dc) = require_discord(session) else {
        return;
    };
    if session.channel_id == "0" {
        eprintln!("No channel selected. Run 'open <channel_id>' first.");
        return;
    }

    println!(
        "--- Live Encrypted Chat [channel {} | {}] ---",
        session.channel_id,
        session.preset.label()
    );
    println!("Type any message and press Enter to encrypt & send.");
    println!("Slash commands: /file <path> | /dl <num> [out] | /key | /q (exit chat)\n");

    let mut last_id = String::new();
    match dc.get_messages(&session.channel_id, 10) {
        Ok(mut msgs) => {
            msgs.reverse();
            let key = session.current_key();
            for m in &msgs {
                render_message(m, &key, &session.attachments);
                last_id = m.id.clone();
            }
        }
        Err(e) => eprintln!("Initial fetch failed: {e}"),
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let dc_bg = Arc::clone(&dc);
    let key_bg = Arc::clone(&session.key);
    let att_bg = Arc::clone(&session.attachments);
    let ch_bg = session.channel_id.clone();
    let my_id = dc.me.id.clone();

    let poller = thread::spawn(move || {
        let mut cursor = last_id;
        while !stop_bg.load(Ordering::Relaxed) {
            for _ in 0..20 {
                if stop_bg.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let fetched = if cursor.is_empty() {
                dc_bg.get_messages(&ch_bg, 5)
            } else {
                dc_bg.get_messages_after(&ch_bg, &cursor)
            };
            if let Ok(mut msgs) = fetched {
                msgs.reverse();
                let key = Arc::clone(&key_bg.read().unwrap());
                for m in &msgs {
                    cursor = m.id.clone();
                    if m.author.id == my_id && m.attachments.is_empty() {
                        // Already echoed locally when sent.
                        continue;
                    }
                    render_message(m, &key, &att_bg);
                }
            }
        }
    });

    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("Input error: {e}");
                break;
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "/q" || trimmed == "/exit" {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("/file ") {
            handle_send_file(session, rest);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("/dl ") {
            handle_download_attachment(session, rest);
            continue;
        }
        if trimmed == "/key" || trimmed.starts_with("/key ") {
            let rest = trimmed.strip_prefix("/key").unwrap_or("").trim();
            handle_switch_key(session, rest);
            continue;
        }

        let key = session.current_key();
        match encrypt_message(trimmed, &key, session.preset, &session.channel_id, &dc.me.id) {
            Ok(wire) => match dc.send_message(&session.channel_id, &wire) {
                Ok(_) => println!("[🔓 {} (you)]: {}", dc.me.display_name(), trimmed),
                Err(e) => eprintln!("Send failed: {e}"),
            },
            Err(e) => eprintln!("Encrypt error: {e}"),
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = poller.join();
    println!("--- Exited live chat ---");
}

fn render_message(
    msg: &DiscordMessage,
    key: &MasterKey,
    attachments: &Arc<Mutex<Vec<CachedAttachment>>>,
) {
    if let Some(ref reply) = msg.referenced_message {
        let reply_ch = reply.channel_id.as_deref().unwrap_or(&msg.channel_id);
        let reply_text = if looks_encrypted(&reply.content) {
            match decrypt_message(&reply.content, key, reply_ch, &reply.author.id) {
                Ok((pt, _)) => format!("🔓 {}", strip_size_tag(&pt)),
                Err(_) => "🔒 (unable to decrypt)".to_string(),
            }
        } else {
            strip_size_tag(&reply.content).to_string()
        };
        println!("  ↳ replying to {}: {}", reply.author.display_name(), reply_text);
    }

    let author = msg.author.display_name();
    if looks_encrypted(&msg.content) {
        match decrypt_message(&msg.content, key, &msg.channel_id, &msg.author.id) {
            Ok((pt, preset)) => {
                let cleaned = strip_size_tag(&pt);
                println!("[🔓 {author}] ({}): {}", preset.label(), cleaned);
            }
            Err(_) => {
                println!("[🔒 {author}] (wrong key or forced channel key needed)");
            }
        }
    } else if !msg.content.is_empty() {
        println!("[{author}]: {}", msg.content);
    } else if !msg.attachments.is_empty() {
        println!("[{author}] sent attachment(s):");
    }

    if !msg.attachments.is_empty() {
        let mut cache = attachments.lock().unwrap();
        for att in &msg.attachments {
            cache.push(CachedAttachment {
                channel_id: msg.channel_id.clone(),
                author_id: msg.author.id.clone(),
                filename: att.filename.clone(),
                url: att.url.clone(),
            });
            let num = cache.len();
            println!(
                "    [Attachment #{num}] {} ({}) — run `dl {num}` to decrypt",
                att.filename,
                fmt_bytes(att.size)
            );
        }
    }
}

// ------------------------------------------------------------ Offline / Local

fn handle_encrypt_text(session: &Session, rest: &str) {
    let (ch_ov, sender_ov, preset_ov, text) = parse_text_flags(rest);
    if text.is_empty() {
        eprintln!("Usage: e [-c channel_id] [-s sender_id] [-p aes128|192|256] <message>");
        return;
    }
    let ch = ch_ov.as_deref().unwrap_or(&session.channel_id);
    let sender = sender_ov.as_deref().unwrap_or(&session.sender_id);
    let preset = preset_ov.unwrap_or(session.preset);
    let key = session.current_key();

    match encrypt_message(text, &key, preset, ch, sender) {
        Ok(wire) => println!("{wire}"),
        Err(e) => eprintln!("Encrypt error: {e}"),
    }
}

fn handle_decrypt_text(session: &Session, rest: &str) {
    let (ch_ov, sender_ov, _preset_ov, wire) = parse_text_flags(rest);
    if wire.is_empty() {
        eprintln!("Usage: d [-c channel_id] [-s sender_id] <§ciphertext>");
        return;
    }
    let ch = ch_ov.as_deref().unwrap_or(&session.channel_id);
    let sender = sender_ov.as_deref().unwrap_or(&session.sender_id);
    let key = session.current_key();

    match decrypt_message(wire, &key, ch, sender) {
        Ok((plain, preset)) => {
            println!("[{}]\n{}", preset.label(), strip_size_tag(&plain));
            return;
        }
        Err(first_err) => {
            // If logged in and no explicit -s override was given, try auto-matching the real author from Discord.
            if sender_ov.is_none() && ch != "0" {
                if let Some(ref dc) = session.discord {
                    if let Ok(msgs) = dc.get_messages(ch, 50) {
                        let target = wire.trim();
                        if let Some(m) = msgs.iter().find(|m| m.content.trim() == target) {
                            if let Ok((plain, preset)) =
                                decrypt_message(target, &key, &m.channel_id, &m.author.id)
                            {
                                println!(
                                    "[🔓 {} ({}) | {}]\n{}",
                                    m.author.display_name(),
                                    m.author.id,
                                    preset.label(),
                                    strip_size_tag(&plain)
                                );
                                return;
                            }
                        }
                    }
                }
            }
            eprintln!("Decrypt error: {first_err}");
            if session.discord.is_none() && sender_ov.is_none() {
                eprintln!(
                    "Hint: If someone else sent this message, pass their user ID (`d -s <author_id> §...`) or run 'login' to auto-detect."
                );
            }
        }
    }
}

fn handle_encrypt_file(session: &Session, rest: &str) {
    let tokens = match split_shell_args(rest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Argument parse error: {e}");
            return;
        }
    };

    let mut ch_ov: Option<String> = None;
    let mut sender_ov: Option<String> = None;
    let mut preset_ov: Option<Preset> = None;
    let mut pos: Vec<String> = Vec::new();

    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-c" | "--channel" if i + 1 < tokens.len() => {
                ch_ov = Some(tokens[i + 1].clone());
                i += 2;
            }
            "-s" | "--sender" if i + 1 < tokens.len() => {
                sender_ov = Some(tokens[i + 1].clone());
                i += 2;
            }
            "-p" | "--preset" if i + 1 < tokens.len() => {
                match Preset::parse(&tokens[i + 1]) {
                    Some(p) => preset_ov = Some(p),
                    None => {
                        eprintln!("Invalid preset '{}'", tokens[i + 1]);
                        return;
                    }
                }
                i += 2;
            }
            _ => {
                pos.push(tokens[i].clone());
                i += 1;
            }
        }
    }

    if pos.is_empty() || pos.len() > 2 {
        eprintln!("Usage: ef [-c channel_id] [-s sender_id] [-p preset] <input_file> [output_file]");
        return;
    }

    let in_path = PathBuf::from(&pos[0]);
    let out_path = if pos.len() == 2 {
        PathBuf::from(&pos[1])
    } else {
        PathBuf::from(format!("{}.aeg", pos[0]))
    };

    if same_path(&in_path, &out_path) {
        eprintln!("Error: input and output paths must be different.");
        return;
    }

    let in_file = match File::open(&in_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open '{}': {e}", in_path.display());
            return;
        }
    };
    let out_file = match File::create(&out_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot create '{}': {e}", out_path.display());
            return;
        }
    };

    let ch = ch_ov.as_deref().unwrap_or(&session.channel_id);
    let sender = sender_ov.as_deref().unwrap_or(&session.sender_id);
    let preset = preset_ov.unwrap_or(session.preset);
    let key = session.current_key();

    let start = Instant::now();
    let mut reader = BufReader::new(in_file);
    let mut writer = BufWriter::new(out_file);

    match encrypt_stream(&mut reader, &mut writer, &key, preset, ch, sender) {
        Ok(bytes) => println!(
            "Encrypted {} ({}) -> '{}' in {:.2}s",
            fmt_bytes(bytes),
            preset.label(),
            out_path.display(),
            start.elapsed().as_secs_f64()
        ),
        Err(e) => {
            drop(writer);
            let _ = fs::remove_file(&out_path);
            eprintln!("File encryption failed: {e}");
        }
    }
}

fn handle_decrypt_file(session: &Session, rest: &str) {
    let tokens = match split_shell_args(rest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Argument parse error: {e}");
            return;
        }
    };

    let mut ch_ov: Option<String> = None;
    let mut sender_ov: Option<String> = None;
    let mut pos: Vec<String> = Vec::new();

    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-c" | "--channel" if i + 1 < tokens.len() => {
                ch_ov = Some(tokens[i + 1].clone());
                i += 2;
            }
            "-s" | "--sender" if i + 1 < tokens.len() => {
                sender_ov = Some(tokens[i + 1].clone());
                i += 2;
            }
            _ => {
                pos.push(tokens[i].clone());
                i += 1;
            }
        }
    }

    if pos.is_empty() || pos.len() > 2 {
        eprintln!("Usage: df [-c channel_id] [-s sender_id] <encrypted_file> [output_file]");
        return;
    }

    let in_path = PathBuf::from(&pos[0]);
    let out_path = if pos.len() == 2 {
        PathBuf::from(&pos[1])
    } else if let Some(stripped) = pos[0].strip_suffix(".aeg") {
        PathBuf::from(stripped)
    } else {
        PathBuf::from(format!("{}.dec", pos[0]))
    };

    if same_path(&in_path, &out_path) {
        eprintln!("Error: input and output paths must be different.");
        return;
    }

    let in_file = match File::open(&in_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open '{}': {e}", in_path.display());
            return;
        }
    };
    let out_file = match File::create(&out_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot create '{}': {e}", out_path.display());
            return;
        }
    };

    let ch = ch_ov.as_deref().unwrap_or(&session.channel_id);
    let sender = sender_ov.as_deref().unwrap_or(&session.sender_id);
    let key = session.current_key();

    let start = Instant::now();
    let mut reader = BufReader::new(in_file);
    let mut writer = BufWriter::new(out_file);

    match decrypt_stream(&mut reader, &mut writer, &key, ch, sender) {
        Ok((bytes, preset)) => println!(
            "Decrypted {} ({}) -> '{}' in {:.2}s",
            fmt_bytes(bytes),
            preset.label(),
            out_path.display(),
            start.elapsed().as_secs_f64()
        ),
        Err(e) => {
            drop(writer);
            let _ = fs::remove_file(&out_path);
            eprintln!("File decryption failed (partial output deleted): {e}");
        }
    }
}

fn handle_switch_key(session: &mut Session, rest: &str) {
    let tokens = match split_shell_args(rest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Argument parse error: {e}");
            return;
        }
    };

    let context = if tokens.is_empty() {
        None
    } else if (tokens[0] == "--ctx" || tokens[0] == "--context") && tokens.len() == 2 {
        Some(tokens[1].as_str())
    } else {
        eprintln!("Usage: key [--ctx <context>]");
        return;
    };

    match prompt_and_derive(context) {
        Ok((new_key, label)) => {
            session.replace_key(new_key, label);
            println!("Switched active key to [{}]. Previous key wiped.", session.key_label);
        }
        Err(e) => eprintln!("Key switch cancelled: {e}"),
    }
}

fn handle_forced_channel(session: &mut Session, rest: &str) {
    let ch = rest.trim();
    if ch.is_empty() {
        eprintln!("Usage: forced <channel_id>");
        return;
    }
    match forced_channel_password(ch) {
        Some(pw) => {
            let ctx = format!("forced|{ch}");
            print!("Deriving forced key for channel {ch}...");
            let _ = io::stdout().flush();
            let start = Instant::now();
            match derive_context_key(pw, &ctx) {
                Ok(new_key) => {
                    session.replace_key(new_key, format!("ctx:{ctx}"));
                    session.channel_id = ch.to_string();
                    println!(
                        " done in {:.0} ms. Active channel set to {ch}.",
                        start.elapsed().as_secs_f64() * 1000.0
                    );
                }
                Err(e) => eprintln!("\nDerivation failed: {e}"),
            }
        }
        None => eprintln!(
            "No built-in forced key for channel '{ch}'. Use `key --ctx forced|{ch}` to enter one manually."
        ),
    }
}

fn handle_set(session: &mut Session, rest: &str) {
    let (field, val) = split_first_word(rest);
    let val = val.trim();
    if field.is_empty() || val.is_empty() {
        eprintln!("Usage: set <channel|sender|preset> <value>");
        return;
    }
    match field.to_ascii_lowercase().as_str() {
        "channel" | "ch" | "c" => {
            session.channel_id = val.to_string();
            println!("Channel ID -> {}", session.channel_id);
        }
        "sender" | "author" | "s" => {
            session.sender_id = val.to_string();
            println!("Sender ID  -> {}", session.sender_id);
        }
        "preset" | "p" => match Preset::parse(val) {
            Some(p) => {
                session.preset = p;
                println!(
                    "Preset     -> {} (max text: {} bytes)",
                    p.label(),
                    max_plaintext_bytes(p)
                );
            }
            None => eprintln!("Invalid preset '{val}'. Use: aes128, aes192, or aes256."),
        },
        other => eprintln!("Unknown setting '{other}'. Use: channel, sender, or preset."),
    }
}

fn handle_status(session: &Session) {
    match &session.discord {
        Some(dc) => println!(
            "  Discord    : {} (@{}, ID: {})",
            dc.me.display_name(),
            dc.me.username,
            dc.me.id
        ),
        None => println!("  Discord    : offline (run 'login' to connect)"),
    }
    println!("  Key mode   : {} (in RAM, zeroized on drop)", session.key_label);
    println!(
        "  Preset     : {} (max text: {} bytes)",
        session.preset.label(),
        max_plaintext_bytes(session.preset)
    );
    println!("  Channel ID : {}", session.channel_id);
    println!("  Sender ID  : {}", session.sender_id);
}

// ------------------------------------------------------------------ Helpers

fn strip_size_tag(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix("[sz:") {
        if let Some(end) = rest.find(']') {
            let inner = &rest[..end];
            if let Some((w, h)) = inner.split_once(',') {
                if !w.is_empty()
                    && !h.is_empty()
                    && w.bytes().all(|b| b.is_ascii_digit())
                    && h.bytes().all(|b| b.is_ascii_digit())
                {
                    return &rest[end + 1..];
                }
            }
        }
    }
    s
}

fn parse_discord_link(input: &str) -> Option<(String, Option<String>)> {
    let s = input.trim();
    let idx = s.find("/channels/")?;
    if !s.starts_with("https://") && !s.starts_with("http://") {
        return None;
    }
    let after = &s[idx + "/channels/".len()..];
    let clean = after.split(['?', '#']).next()?;
    let parts: Vec<&str> = clean.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 3
        && parts[1].bytes().all(|b| b.is_ascii_digit())
        && parts[2].bytes().all(|b| b.is_ascii_digit())
    {
        Some((parts[1].to_string(), Some(parts[2].to_string())))
    } else if parts.len() == 2 && parts[1].bytes().all(|b| b.is_ascii_digit()) {
        Some((parts[1].to_string(), None))
    } else {
        None
    }
}

fn split_first_word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.find(|c: char| c.is_ascii_whitespace()) {
        Some(idx) => (&s[..idx], s[idx..].trim_start()),
        None => (s, ""),
    }
}

fn parse_text_flags(input: &str) -> (Option<String>, Option<String>, Option<Preset>, &str) {
    let mut ch = None;
    let mut sender = None;
    let mut preset = None;
    let mut cur = input.trim_start();

    loop {
        let (tok, after_tok) = split_first_word(cur);
        match tok {
            "-c" | "--channel" => {
                let (val, after_val) = split_first_word(after_tok);
                if val.is_empty() {
                    break;
                }
                ch = Some(val.to_string());
                cur = after_val;
            }
            "-s" | "--sender" => {
                let (val, after_val) = split_first_word(after_tok);
                if val.is_empty() {
                    break;
                }
                sender = Some(val.to_string());
                cur = after_val;
            }
            "-p" | "--preset" => {
                let (val, after_val) = split_first_word(after_tok);
                if let Some(p) = Preset::parse(val) {
                    preset = Some(p);
                    cur = after_val;
                } else {
                    break;
                }
            }
            "--" => {
                cur = after_tok;
                break;
            }
            _ => break,
        }
    }

    (ch, sender, preset, cur)
}

fn split_shell_args(input: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(&next) = chars.peek() {
                        if next == '"' || next == '\\' {
                            current.push(chars.next().unwrap());
                        } else {
                            current.push(c);
                        }
                    } else {
                        current.push(c);
                    }
                } else {
                    current.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                c if c.is_ascii_whitespace() => {
                    if !current.is_empty() {
                        args.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(c),
            },
        }
    }

    if quote.is_some() {
        return Err("Unclosed quote in arguments".into());
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KiB", b as f64 / 1024.0)
    } else {
        format!("{:.2} MiB", b as f64 / (1024.0 * 1024.0))
    }
}

fn print_cli_usage() {
    println!("Usage: aegires-cli [OPTIONS]");
    println!("  --login                  Prompt for Discord token immediately at startup");
    println!("  -c, --channel <id>       Default Discord channel ID (default: 0)");
    println!("  -s, --sender <id>        Default Discord sender/author ID (default: 0)");
    println!("  -p, --preset <preset>    aes128 | aes192 | aes256 (default: aes256)");
    println!("  --ctx <context>          Derive context-bound key (e.g. forced|<channel_id>)");
    println!("  -h, --help               Show this help");
}

fn print_repl_help() {
    println!("Discord Mode (auto-detects user, channel, and author IDs):");
    println!("  login                         Log in with Discord token (RAM only, auto-sets sender ID)");
    println!("  logout                        Wipe Discord token from RAM");
    println!("  dms                           List your DM channels");
    println!("  guilds                        List your Discord servers");
    println!("  channels <guild_id>           List text channels in a server");
    println!("  open <channel_id|link>        Switch active channel & decrypt latest messages");
    println!("  r [count]                     Fetch & decrypt recent messages (everyone's messages)");
    println!("  s <message>                   Encrypt & send directly to active channel");
    println!("  sendfile <path> [caption]     Encrypt & upload media directly to active channel");
    println!("  dl <num> [out_path]           Download & decrypt attachment #num from 'r'/'chat'");
    println!("  chat                          Live chat mode (type directly to send, auto-decrypts incoming)");
    println!("  <paste Discord link>          Auto-fetch & decrypt that exact message");
    println!("  <paste §ciphertext>           Auto-decrypt (matches channel author if logged in)");
    println!();
    println!("Offline / Local Mode:");
    println!("  e  [-c ch] [-s sender] [-p preset] <text>     Encrypt text -> §base64");
    println!("  d  [-c ch] [-s sender] <§ciphertext>          Decrypt text");
    println!("  ef [-c ch] [-s sender] [-p preset] <in> [out] Encrypt local media/file");
    println!("  df [-c ch] [-s sender] <in> [out]             Decrypt local media/file");
    println!();
    println!("Session:");
    println!("  key [--ctx <context>]         Wipe current key & switch to a new passphrase");
    println!("  forced <channel_id>           Load built-in forced channel key");
    println!("  set <channel|sender|preset>   Update session defaults");
    println!("  status                        Show current session info");
    println!("  exit | quit | q               Wipe key & token from RAM and quit");
}
