fn main() {
    if let Err(e) = vault_family::cli::run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
