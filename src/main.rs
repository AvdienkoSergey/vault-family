#[tokio::main]
async fn main() {
    if let Err(e) = vault_family::cli::run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
