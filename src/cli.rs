use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use crate::config::ConfigPaths;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Codex lightweight credential refresh service"
)]
pub struct CliArgs {
    #[arg(long)]
    pub config: Option<PathBuf>,
}

pub async fn run() -> Result<()> {
    let cli = CliArgs::parse();
    let config_paths = ConfigPaths::from_cli(cli.config);
    crate::web::serve(config_paths).await
}
