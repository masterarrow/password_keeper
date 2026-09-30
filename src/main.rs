use password_keeper::{EResult, init};

#[tokio::main]
async fn main() -> EResult<()> {
    init().await
}
