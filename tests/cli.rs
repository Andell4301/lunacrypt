#![cfg(feature = "cli")]

use std::process::{Command, Stdio};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lunacrypt"));
    command.stdin(Stdio::null());
    command
}

#[test]
fn help_uses_normal_output_and_a_missing_command_prints_an_error() {
    let help = command().arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("\n\nUsage: lunacrypt <COMMAND>\n"));
    assert!(!help.contains("\\u{a}"));

    let missing = command().output().unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    let diagnostic = String::from_utf8(missing.stderr).unwrap();
    assert!(diagnostic.contains("\n\nUsage: lunacrypt <COMMAND>\n"));
    assert!(!diagnostic.contains("\\u{a}"));
}

#[test]
fn unknown_commands_are_printed_with_special_characters_made_visible() {
    let output = command()
        .arg("bad\n\u{001b}[2J\u{202e}name")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("bad\\u{a}\\u{1b}[2J\\u{202e}name"));
    assert!(!diagnostic.contains(['\u{001b}', '\u{202e}']));
    assert!(!diagnostic.contains("bad\n"));
}

#[cfg(unix)]
fn closed_pipe() -> Stdio {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    // Closing one end leaves nowhere for the other end to send bytes. Give
    // that remaining end to the child as stdout or stderr to force BrokenPipe.
    let (output, reader) = UnixStream::pair().unwrap();
    drop(reader);
    Stdio::from(OwnedFd::from(output))
}

/// In `lunacrypt --help | head -n 1`, head may stop reading early.
/// Help should still succeed. An invalid command should still fail even if
/// its error output is connected to a reader that has already closed.
#[cfg(unix)]
#[test]
fn help_succeeds_when_the_reader_stops_early_and_invalid_commands_still_fail() {
    let help = command()
        .arg("--help")
        .stdout(closed_pipe())
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(help.stderr.is_empty());

    let error = command()
        .arg("unknown-command")
        .stderr(closed_pipe())
        .output()
        .unwrap();
    assert_eq!(error.status.code(), Some(2));
    assert!(error.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn help_reports_a_failure_when_its_output_cannot_be_written() {
    use std::os::{fd::OwnedFd, unix::net::UnixDatagram};

    // This socket has no destination, so writing fails for a reason other than
    // a closed pipe. Help lets us test that error without opening a vault or
    // prompting for a password.
    let output_socket = UnixDatagram::unbound().unwrap();
    let output = command()
        .arg("--help")
        .stdout(Stdio::from(OwnedFd::from(output_socket)))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));

    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("failed to write command output"));
    assert!(!diagnostic.contains("panicked"));
}
