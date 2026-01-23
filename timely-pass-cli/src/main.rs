use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

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

    /// Manage policies
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Upgrade the CLI
    Upgrade {
        /// Specific version to upgrade to
        #[arg(long)]
        version: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Add or update a policy
    Add {
        /// Policy ID (overrides ID in file if provided)
        #[arg(long)]
        id: Option<String>,

        /// Path to policy definition file (JSON)
        #[arg(long)]
        file: PathBuf,
    },

    /// Get policy details
    Get {
        /// Policy ID
        #[arg(long)]
        id: String,
    },

    /// List all policies
    List,

    /// Remove a policy
    Remove {
        /// Policy ID
        #[arg(long)]
        id: String,
    },

    /// Update an existing policy
    Update {
        /// Policy ID
        #[arg(long)]
        id: String,

        /// Enable the policy
        #[arg(long, group = "enable_state")]
        enable: bool,

        /// Disable the policy
        #[arg(long, group = "enable_state")]
        disable: bool,

        /// Set clock skew tolerance in seconds
        #[arg(long)]
        skew: Option<u64>,

        /// Set timezone (e.g., "UTC", "America/New_York")
        #[arg(long)]
        timezone: Option<String>,

        /// Set max attempts
        #[arg(long)]
        max_attempts: Option<u32>,

        /// Set single use
        #[arg(long, group = "single_use_state")]
        single_use: bool,

        /// Unset single use
        #[arg(long, group = "single_use_state")]
        multi_use: bool,
    },
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
        Commands::Policy { command } => match command {
            PolicyCommands::Add { id, file } => commands::policy_add(cli.store, id, file).await?,
            PolicyCommands::Get { id } => commands::policy_get(cli.store, id).await?,
            PolicyCommands::List => commands::policy_list(cli.store).await?,
            PolicyCommands::Remove { id } => commands::policy_remove(cli.store, id).await?,
            PolicyCommands::Update { id, enable, disable, skew, timezone, max_attempts, single_use, multi_use } => {
                commands::policy_update(cli.store, id, enable, disable, skew, timezone, max_attempts, single_use, multi_use).await?
            },
        },
        Commands::Upgrade { version } => commands::upgrade(version).await?,
    }

    Ok(())
}
