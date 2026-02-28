use clap::{Parser, Subcommand};
use std::path::PathBuf;

use chrono::Utc;
use uuid::Uuid;

use crate::crypto_operations::RealCrypto;
use crate::password_generator::{Empty, PasswordGenerator};
use crate::sqlite::{Authenticated, Closed, DB};
use crate::types::{
    Email, EntryId, EntryPassword, Login, MasterPassword, PlainEntry, ServiceName, ServiceUrl,
    UserId,
};

#[derive(Parser)]
#[command(name = "vault-family", about = "Type-safe password manager")]
pub struct Cli {
    /// Path to the database file
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register a new user
    Register {
        /// Your email address
        #[arg(long)]
        email: String,
    },
    /// List all entries
    List {
        /// Your email address
        #[arg(long)]
        email: String,
    },
    /// Add a new password entry
    Add {
        /// Your email address
        #[arg(long)]
        email: String,
        /// Service name (e.g., "GitHub")
        #[arg(long)]
        service: String,
        /// Service URL
        #[arg(long)]
        url: String,
        /// Login for this service (email, username, phone, etc.)
        #[arg(long)]
        login: Option<String>,
        /// Notes
        #[arg(long, default_value = "")]
        notes: String,
        /// Auto-generate password with given length
        #[arg(long)]
        generate: Option<usize>,
    },
    /// View a decrypted entry
    View {
        /// Your email address
        #[arg(long)]
        email: String,
        /// Entry ID to view
        id: String,
    },
    /// Delete an entry
    Delete {
        /// Your email address
        #[arg(long)]
        email: String,
        /// Entry ID to delete
        id: String,
    },
    /// Generate a password (no auth needed)
    Generate {
        /// Password length
        #[arg(long, default_value = "16")]
        length: usize,
        /// Include lowercase letters
        #[arg(long)]
        lowercase: bool,
        /// Include uppercase letters
        #[arg(long)]
        uppercase: bool,
        /// Include digits
        #[arg(long)]
        digits: bool,
        /// Include symbols (!@#$%^&*)
        #[arg(long)]
        symbols: bool,
    },
    /// Start http server
    Serve {
        /// Host address
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port number
        #[arg(long, default_value = "3000")]
        port: u16,
    },
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let db_path = resolve_db_path(cli.db)?;

    match cli.command {
        Command::Register { email } => cmd_register(&db_path, email),
        Command::List { email } => cmd_list(&db_path, email),
        Command::Add {
            email,
            service,
            url,
            login,
            notes,
            generate,
        } => cmd_add(&db_path, email, service, url, login, notes, generate),
        Command::View { email, id } => cmd_view(&db_path, email, id),
        Command::Delete { email, id } => cmd_delete(&db_path, email, id),
        Command::Generate {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
        } => cmd_generate(length, lowercase, uppercase, digits, symbols),
        Command::Serve { host, port } => Ok(cmd_serve(&host, port, db_path).await?),
    }
}

// ════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════

fn resolve_db_path(explicit: Option<PathBuf>) -> Result<String, Box<dyn std::error::Error>> {
    let path = match explicit {
        Some(p) => p,
        None => {
            let data_dir = dirs::data_dir().ok_or("Could not determine data directory")?;
            let vault_dir = data_dir.join("vault-family");
            std::fs::create_dir_all(&vault_dir)?;
            vault_dir.join("vault.db")
        }
    };
    Ok(path.to_string_lossy().into_owned())
}

fn open_and_authenticate(
    db_path: &str,
    email: String,
) -> Result<DB<Authenticated, RealCrypto>, Box<dyn std::error::Error>> {
    let email = Email::parse(email)?;
    let master = rpassword::prompt_password("Master password: ")?;

    let db = DB::<Closed, RealCrypto>::new(RealCrypto).open(db_path)?;

    let db = db.authenticate(email, MasterPassword::new(master))?;

    Ok(db)
}

// ════════════════════════════════════════════
// Command handlers
// ════════════════════════════════════════════

fn cmd_register(db_path: &str, email: String) -> Result<(), Box<dyn std::error::Error>> {
    let email = Email::parse(email)?;
    let master = rpassword::prompt_password("Master password: ")?;
    let confirm = rpassword::prompt_password("Confirm master password: ")?;

    if master != confirm {
        return Err("Passwords do not match".into());
    }

    let db = DB::<Closed, RealCrypto>::new(RealCrypto).open(db_path)?;

    let user = db.create_user(email, MasterPassword::new(master))?;

    println!("User registered successfully.");
    println!("Your user ID: {}", user.id.as_str());

    Ok(())
}

fn cmd_list(db_path: &str, email: String) -> Result<(), Box<dyn std::error::Error>> {
    let db = open_and_authenticate(db_path, email)?;

    let user_id = UserId::new(db.user_id().as_str().to_string());
    let entries = db.list_entries(&user_id)?;

    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("{:<38} {:<20} Service", "ID", "Created");
    println!("{}", "-".repeat(70));

    for entry in &entries {
        let plain = db.decrypt(entry)?;
        println!(
            "{:<38} {:<20} {}",
            entry.id.as_str(),
            entry.created_at.format("%Y-%m-%d %H:%M"),
            plain.service_name.as_str(),
        );
    }

    Ok(())
}

fn cmd_add(
    db_path: &str,
    email: String,
    service: String,
    url: String,
    login: Option<String>,
    notes: String,
    generate_len: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = open_and_authenticate(db_path, email.clone())?;

    let entry_password = match generate_len {
        Some(len) => {
            let pw = PasswordGenerator::<Empty, 8>::from_flags(len, true, true, true, true);
            let password = pw.generate();
            println!("Generated password: {}", password.as_str());
            password.as_str().to_string()
        }
        None => rpassword::prompt_password("Entry password: ")?,
    };

    let now = Utc::now();
    let plain = PlainEntry {
        id: EntryId::new(Uuid::new_v4().to_string()),
        user_id: UserId::new(db.user_id().as_str().to_string()),
        service_name: ServiceName::new(service),
        service_url: ServiceUrl::new(url),
        login: Login::new(login.unwrap_or(email)),
        password: EntryPassword::new(entry_password),
        notes,
        created_at: now,
        updated_at: now,
    };

    let entry_id = plain.id.as_str().to_string();
    let encrypted = db.encrypt(&plain)?;
    db.save_entry(&encrypted)?;

    println!("Entry saved: {}", entry_id);

    Ok(())
}

fn cmd_view(db_path: &str, email: String, id: String) -> Result<(), Box<dyn std::error::Error>> {
    let db = open_and_authenticate(db_path, email)?;

    let user_id = UserId::new(db.user_id().as_str().to_string());
    let entries = db.list_entries(&user_id)?;

    let entry = entries
        .iter()
        .find(|e| e.id.as_str() == id)
        .ok_or("Entry not found")?;

    let plain = db.decrypt(entry)?;

    println!("Service:  {}", plain.service_name.as_str());
    println!("URL:      {}", plain.service_url.as_str());
    println!("Login:    {}", plain.login.as_str());
    println!("Password: {}", plain.password.as_str());
    println!("Notes:    {}", plain.notes);
    println!("Created:  {}", plain.created_at);
    println!("Updated:  {}", plain.updated_at);

    Ok(())
}

fn cmd_delete(db_path: &str, email: String, id: String) -> Result<(), Box<dyn std::error::Error>> {
    let db = open_and_authenticate(db_path, email)?;

    let deleted = db.delete_entry(&EntryId::new(id))?;

    if deleted {
        println!("Entry deleted.");
    } else {
        println!("Entry not found or already deleted.");
    }

    Ok(())
}

fn cmd_generate(
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let all_defaults = !lowercase && !uppercase && !digits && !symbols;

    let generator = PasswordGenerator::<Empty, 8>::from_flags(
        length,
        lowercase || all_defaults,
        uppercase || all_defaults,
        digits || all_defaults,
        symbols || all_defaults,
    );

    let password = generator.generate();
    println!("{}", password.as_str());

    Ok(())
}

async fn cmd_serve(
    host: &str,
    port: u16,
    db_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::http_api::run_server(host, port, db_path).await?;
    Ok(())
}
