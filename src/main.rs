#[tokio::main]
async fn main() -> anyhow::Result<()> {
    token_refresh::cli::run().await
}
