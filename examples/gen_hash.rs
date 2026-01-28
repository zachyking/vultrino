fn main() {
    let hash = bcrypt::hash("admin123", bcrypt::DEFAULT_COST).unwrap();
    let json = serde_json::json!({
        "username": "admin",
        "password_hash": hash
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
