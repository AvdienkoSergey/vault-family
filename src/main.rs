#[tokio::main]
async fn main() {
    // Load .env before anything else (missing file is OK)
    dotenvy::dotenv().ok();

    if let Err(e) = vault_family::cli::run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
