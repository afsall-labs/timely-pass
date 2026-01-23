use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod tui;

#[derive(Parser)]
#[command(name = "timely-pass")]
#[command(about = "Time-based password policies manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to the secret store
    #[arg(short, long, default_value = "store.timely")]
    store: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new encrypted store
    Init,

    /// Add a new credential
    Add {
        /// Credential ID/Label
        #[arg(long)]
        id: String,

        /// Type of secret (password, key, token)
        #[arg(long, default_value = "password")]
        type_: String,

        /// Path to policy file (TOML)
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Provide secret via stdin or prompt
        #[arg(long, action)]
        secret: bool,
    },

    /// Get a credential
    Get {
        /// Credential ID/Label
        #[arg(long)]
        id: String,
    },

    /// Evaluate a policy
    Eval {
        /// Path to policy file
        #[arg(long)]
        policy: PathBuf,

        /// Time to evaluate against (ISO 8601)
        #[arg(long)]
        time: Option<String>,
    },

    /// Rotate a credential
    Rotate {
        /// Credential ID
        #[arg(long)]
        id: String,
    },

    /// List credentials
    List,

    /// Remove a credential
    Remove {
        /// Credential ID
        #[arg(long)]
        id: String,
    },

    /// Launch interactive TUI
    Ui,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => commands::init(cli.store).await?,
        Commands::Add { id, type_, policy, secret } => commands::add(cli.store, id, type_, policy, secret).await?,
        Commands::Get { id } => commands::get(cli.store, id).await?,
        Commands::Eval { policy, time } => commands::eval(policy, time).await?,
        Commands::Rotate { id } => commands::rotate(cli.store, id).await?,
        Commands::List => commands::list(cli.store).await?,
        Commands::Remove { id } => commands::remove(cli.store, id).await?,
        Commands::Ui => tui::run(cli.store).await?,
    }

    Ok(())
}
