mod import;
mod output;
mod password;

use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use byte_unit::{Byte, ParseError, UnitType, ValueParseError};
use clap::{
    Parser, Subcommand, ValueEnum,
    error::{ContextKind, ContextValue},
};
use lunacrypt::{AccessMode, CipherId, CreateOptions, VaultError, Volume};

use self::{
    import::resolve_vault_destination,
    output::{build_tree, terminal_safe, terminal_safe_display, terminal_safe_path, write_tree},
    password::{prompt_and_confirm_new_password, prompt_and_open_volume},
};

const LONG_ABOUT: &str = "\
LunaCrypt stores files in a fixed-capacity encrypted vault.

Sizes accept byte counts or decimal/binary units, such as MB or MiB, through EB/EiB.
Fractional sizes are supported.
Start numbers with a digit, such as 0.5 MiB.
Vault paths are slash-separated portable UTF-8 paths. Extraction never
silently overwrites an existing file and authenticates each file before
publishing its destination name.";

fn parse_size(input: &str) -> Result<u64, String> {
    let size = Byte::parse_str(input, true).map_err(|error| {
        // Clap already shows the rejected value in a part of the message we
        // escape. The error returned here mustn't repeat the raw input outside
        // that step, so use fixed wording instead of the dependency's error text.
        match error {
            ParseError::Value(
                ValueParseError::ExceededBounds(_) | ValueParseError::NumberTooLong,
            ) => "size is too large",
            _ => "invalid size",
        }
        .to_string()
    })?;
    size.as_u64_checked()
        .ok_or_else(|| "size is too large".to_string())
}

fn parse_chunk_size(input: &str) -> Result<u32, String> {
    u32::try_from(parse_size(input)?).map_err(|_| "chunk size exceeds the u32 limit".to_string())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        let adjusted = Byte::from_u64(bytes).get_appropriate_unit(UnitType::Binary);
        format!("{adjusted:.1}")
    }
}

#[derive(Parser)]
#[command(name = "lunacrypt", bin_name = "lunacrypt", version, about = "Encrypted file-vault CLI", long_about = LONG_ABOUT)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CipherChoice {
    #[value(
        name = "chacha",
        alias = "xchacha20-poly1305",
        help = "XChaCha20-Poly1305"
    )]
    XChaCha20Poly1305,
    #[value(name = "aes", alias = "aes-256-gcm-siv", help = "AES-256-GCM-SIV")]
    Aes256GcmSiv,
}

impl From<CipherChoice> for CipherId {
    fn from(cipher: CipherChoice) -> Self {
        match cipher {
            CipherChoice::XChaCha20Poly1305 => Self::XChaCha20Poly1305,
            CipherChoice::Aes256GcmSiv => Self::Aes256GcmSiv,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    Create {
        path: PathBuf,
        #[arg(long, value_parser = parse_size)]
        size: u64,
        #[arg(long, value_parser = parse_chunk_size, default_value = "64KiB")]
        chunk_size: u32,
        #[arg(
            long,
            value_enum,
            default_value = "chacha",
            help = "Cipher for headers, file contents, and the catalog"
        )]
        cipher: CipherChoice,
        #[arg(
            long,
            value_parser = parse_size,
            help = "Usable plaintext capacity per catalog copy; two copies are stored (default: automatic)"
        )]
        metadata_capacity: Option<u64>,
        #[arg(
            long,
            help = "Random-fill the complete post-header record area before publishing; disables sparse-file savings"
        )]
        fill: bool,
    },
    /// Add a regular file or a folder and its contents.
    Add {
        container: PathBuf,
        source: PathBuf,
        #[arg(long, help = "Portable destination path inside the vault")]
        dest: Option<String>,
    },
    /// Create a folder inside the vault.
    Mkdir { container: PathBuf, path: String },
    /// Extract a file or folder without overwriting existing files.
    Extract {
        container: PathBuf,
        source: String,
        destination: PathBuf,
    },
    /// List vault contents.
    List { container: PathBuf },
    /// Show capacity, free space, update numbers, and the health of saved copies.
    Info { container: PathBuf },
    /// Check every current file for damaged or altered contents.
    Verify { container: PathBuf },
    /// Remove a file or folder.
    Remove {
        container: PathBuf,
        path: String,
        #[arg(long)]
        recursive: bool,
    },
    /// Change the password while keeping the same master key.
    ChangePassword { container: PathBuf },
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("failed to write command output: {0}")]
    Output(#[from] io::Error),
}

pub(crate) fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return report_parse_error(error),
    };

    let mut output = io::stdout().lock();
    let result =
        execute_command(cli, &mut output).and_then(|()| output.flush().map_err(CliError::Output));
    finish_output(result, ExitCode::SUCCESS, &mut io::stderr().lock())
}

fn report_parse_error(mut error: clap::Error) -> ExitCode {
    // Clap also sends help and version requests through this path. Their status
    // is success, so an Error here doesn't necessarily mean the command failed.
    let exit_code = ExitCode::from(error.exit_code() as u8);
    sanitize_parse_error(&mut error);
    let result = error.print().and_then(|()| {
        if error.use_stderr() {
            io::stderr().lock().flush()
        } else {
            io::stdout().lock().flush()
        }
    });
    finish_output(
        result.map_err(CliError::Output),
        exit_code,
        &mut io::stderr().lock(),
    )
}

fn finish_output(
    result: Result<(), CliError>,
    expected_exit: ExitCode,
    diagnostics: &mut impl Write,
) -> ExitCode {
    match result {
        Ok(()) => expected_exit,
        // In `lunacrypt --help | head -n 1`, head can stop reading early. Keep
        // the status we already chose: help still succeeds, while an invalid
        // command still fails even if its error message can't be fully written.
        Err(CliError::Output(error)) if error.kind() == io::ErrorKind::BrokenPipe => expected_exit,
        Err(error) => {
            // We may already be reporting a write failure. If stderr fails too,
            // there's nowhere else to send the message, so ignore that write
            // error and return a failure status below.
            let _ = writeln!(diagnostics, "Error: {}", terminal_safe_display(&error))
                .and_then(|()| diagnostics.flush());
            if expected_exit == ExitCode::SUCCESS {
                ExitCode::FAILURE
            } else {
                expected_exit
            }
        }
    }
}

/// Escape user-supplied text before Clap formats an argument error.
/// We escape the individual pieces so Clap's own line breaks and layout stay
/// readable. Usage comes from our command definitions and fixed program name,
/// so it doesn't need escaping here. Custom parsers must also avoid repeating
/// raw input in their error messages, as parse_size does above.
fn sanitize_parse_error(error: &mut clap::Error) {
    let contexts: Vec<_> = error
        .context()
        .filter(|(kind, _)| *kind != ContextKind::Usage)
        .filter_map(|(kind, value)| {
            let safe = match value {
                ContextValue::String(text) => ContextValue::String(terminal_safe(text).to_string()),
                ContextValue::Strings(texts) => ContextValue::Strings(
                    texts
                        .iter()
                        .map(|text| terminal_safe(text).to_string())
                        .collect(),
                ),
                ContextValue::StyledStr(text) => {
                    ContextValue::StyledStr(terminal_safe_display(text).to_string().into())
                }
                ContextValue::StyledStrs(texts) => ContextValue::StyledStrs(
                    texts
                        .iter()
                        .map(|text| terminal_safe_display(text).to_string().into())
                        .collect(),
                ),
                _ => return None,
            };
            Some((kind, safe))
        })
        .collect();
    for (kind, value) in contexts {
        error.insert(kind, value);
    }
}

fn execute_command(cli: Cli, output: &mut impl Write) -> Result<(), CliError> {
    match cli.command {
        Command::Create {
            path,
            size,
            chunk_size,
            cipher,
            metadata_capacity,
            fill,
        } => {
            let password = prompt_and_confirm_new_password()?;
            let volume = Volume::create_container_with_options(
                &path,
                &password,
                size,
                chunk_size,
                CreateOptions {
                    cipher: cipher.into(),
                    metadata_capacity,
                    fill_data_area: fill,
                },
            )?;
            drop(password);
            let info = volume.info()?;
            writeln!(
                output,
                "Created '{}' using {} with {} usable capacity and {} catalog capacity per copy",
                terminal_safe_path(&path),
                info.cipher,
                format_size(info.data_capacity),
                format_size(info.metadata_capacity)
            )?;
        }
        Command::Add {
            container,
            source,
            dest,
        } => {
            let mut volume = prompt_and_open_volume(&container, AccessMode::ReadWrite)?;
            let vault_path = resolve_vault_destination(dest, &source)?;
            let report = volume.import_path(&source, &vault_path)?;
            if report.directories_imported != 0 {
                writeln!(
                    output,
                    "Added {} file(s) and {} directory entry/entries under '{}'",
                    report.files_imported,
                    report.directories_imported,
                    terminal_safe(&vault_path)
                )?;
            } else {
                writeln!(
                    output,
                    "Added '{}' ({})",
                    terminal_safe(&vault_path),
                    format_size(report.bytes_imported)
                )?;
            }
        }
        Command::Mkdir { container, path } => {
            let mut volume = prompt_and_open_volume(&container, AccessMode::ReadWrite)?;
            volume.mkdir(&path)?;
            writeln!(output, "Created '{}'", terminal_safe(&path))?;
        }
        Command::Extract {
            container,
            source,
            destination,
        } => {
            let volume = prompt_and_open_volume(&container, AccessMode::ReadOnly)?;
            if volume.stat(&source)?.is_directory {
                volume.extract_tree_to_directory(&source, &destination)?;
            } else {
                volume.extract_file_to_path(&source, &destination)?;
            }
            writeln!(
                output,
                "Extracted '{}' to '{}'",
                terminal_safe(&source),
                terminal_safe_path(&destination)
            )?;
        }
        Command::List { container } => {
            let volume = prompt_and_open_volume(&container, AccessMode::ReadOnly)?;
            let files = volume.list_files()?;
            if files.is_empty() {
                writeln!(output, "(empty vault)")?;
            } else {
                write_tree(output, &build_tree(&files), 0)?;
            }
        }
        Command::Info { container } => {
            let volume = prompt_and_open_volume(&container, AccessMode::ReadOnly)?;
            let info = volume.info()?;
            writeln!(
                output,
                "Location: {}",
                terminal_safe_display(&info.location)
            )?;
            writeln!(output, "Cipher: {}", info.cipher)?;
            writeln!(output, "Capacity: {}", format_size(info.data_capacity))?;
            writeln!(output, "Used: {}", format_size(info.data_used))?;
            writeln!(output, "Free: {}", format_size(info.free_space))?;
            writeln!(
                output,
                "Catalog plaintext: {} / {} per copy",
                format_size(info.metadata_used),
                format_size(info.metadata_capacity)
            )?;
            writeln!(
                output,
                "Chunk size: {}",
                format_size(info.chunk_size as u64)
            )?;
            writeln!(output, "Entries: {}", info.file_count)?;
            writeln!(output, "Header generation: {}", info.header_generation)?;
            writeln!(output, "Metadata generation: {}", info.metadata_generation)?;
            writeln!(
                output,
                "Redundancy: {}",
                if info.redundancy_degraded {
                    "degraded (open read-write to repair)"
                } else {
                    "healthy"
                }
            )?;
        }
        Command::Verify { container } => {
            let volume = prompt_and_open_volume(&container, AccessMode::ReadOnly)?;
            let report = volume.verify()?;
            writeln!(
                output,
                "Verified {} file(s), {} chunk(s), {}",
                report.files_verified,
                report.chunks_verified,
                format_size(report.bytes_verified)
            )?;
        }
        Command::Remove {
            container,
            path,
            recursive,
        } => {
            let mut volume = prompt_and_open_volume(&container, AccessMode::ReadWrite)?;
            volume.remove(&path, recursive)?;
            writeln!(output, "Removed '{}'", terminal_safe(&path))?;
        }
        Command::ChangePassword { container } => {
            let mut volume = prompt_and_open_volume(&container, AccessMode::ReadWrite)?;
            let new_password = prompt_and_confirm_new_password()?;
            volume.change_password(&new_password)?;
            drop(new_password);
            writeln!(
                output,
                "Changed the password for '{}'",
                terminal_safe_path(&container)
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
