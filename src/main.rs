mod crypto_operations;
mod password_generator;
mod sqlite;
mod types;

fn main() {
    password_generator::demo();
    sqlite::demo();
}
