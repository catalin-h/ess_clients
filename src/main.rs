pub mod ess;

use anyhow::Result;
use clap::{Parser, Subcommand};
use ess::EssBuilder;
use ess::{ConnectionDetails, User, UserUpdate};
use log::{Metadata, Record};

struct SimpleLogger {}

impl log::Log for SimpleLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{}", record.args());
        }
    }

    fn flush(&self) {}
}

#[derive(Subcommand)]
pub enum UserAction {
    /// Insert user
    Add {
        /// The user info
        #[clap(flatten)]
        user: User,
        /// Return plain secret code or as QR code
        #[clap(long, short, action)]
        qr_code: bool,
    },
    /// Update user info & secret except the username
    Update {
        /// The unique user name
        #[clap(value_parser)]
        username: String,
        /// The user data to update
        #[clap(flatten)]
        user_data: UserUpdate,
    },
    /// Verify secret for username
    Verify {
        /// The unique user name
        #[clap(value_parser)]
        username: String,
        /// The OTP code generated by the app
        #[clap(value_parser)]
        one_time_password: String,
    },
    /// Delete user
    Delete {
        /// The unique username
        #[clap(value_parser)]
        username: String,
    },
    /// Get user data by username
    GetUser {
        /// The unique username
        #[clap(value_parser)]
        username: String,
    },
    /// Get all users
    GetAll,
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = false)]
pub struct Cli {
    #[clap(subcommand)]
    /// The user action
    action: UserAction,
    /// The connection details
    #[clap(flatten)]
    conn: ConnectionDetails,
    /// Verbose mode
    #[clap(short, long, action)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    log::set_boxed_logger(Box::new(SimpleLogger {}))
        .map_err(|e| anyhow::anyhow!("Failed to set logger: {}", e))?;

    let cli = Cli::parse();

    log::set_max_level(if cli.verbose {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Info
    });

    let is_pam = cli.conn.pam;
    let client = EssBuilder::new(cli.conn).build()?;

    match cli.action {
        UserAction::Add { user, qr_code } => {
            println!(
                "User created with secret: \n{}",
                client.add_user(user, qr_code).await?
            );
        }
        UserAction::Update {
            username,
            user_data,
        } => {
            client.update_user(&username, user_data).await?;
            println!("Username {} data updated successfully", username);
        }
        UserAction::Delete { username } => {
            client.delete_user(&username).await?;
            println!("Username {} deleted successfully", username);
        }
        UserAction::Verify {
            username,
            one_time_password,
        } => {
            if is_pam {
                ess::verity_username_otp(&username, &one_time_password)?;
            } else {
                client.verify_user(&username, &one_time_password).await?;
            }
            println!("code is OK");
        }
        UserAction::GetUser { username } => {
            println!("User: \n{}", client.get_user(&username).await?);
        }
        UserAction::GetAll => {
            println!("All users: \n{}", client.get_user("all").await?);
        }
    }

    Ok(())
}
