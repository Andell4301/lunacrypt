#![forbid(unsafe_code)]

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
