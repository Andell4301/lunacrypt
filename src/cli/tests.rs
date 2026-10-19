use super::*;

#[test]
fn output_errors_report_failure_except_when_the_reader_stops_early() {
    let mut diagnostics = Vec::new();
    let broken_pipe = || CliError::Output(io::ErrorKind::BrokenPipe.into());
    assert_eq!(
        finish_output(Err(broken_pipe()), ExitCode::SUCCESS, &mut diagnostics),
        ExitCode::SUCCESS
    );
    assert!(diagnostics.is_empty());
    assert_eq!(
        finish_output(Err(broken_pipe()), ExitCode::from(2), &mut diagnostics),
        ExitCode::from(2)
    );
    assert!(diagnostics.is_empty());

    let failure = CliError::Output(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "output\n\u{001b}[2Jdenied",
    ));
    assert_eq!(
        finish_output(Err(failure), ExitCode::SUCCESS, &mut diagnostics),
        ExitCode::FAILURE
    );
    assert_eq!(
        String::from_utf8(diagnostics).unwrap(),
        "Error: failed to write command output: output\\u{a}\\u{1b}[2Jdenied\n"
    );
}

#[test]
fn command_still_reports_failure_when_it_cannot_print_the_error() {
    struct ClosedStderr;
    impl Write for ClosedStderr {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    assert_eq!(
        finish_output(
            Err(CliError::Vault(VaultError::ReadOnly)),
            ExitCode::SUCCESS,
            &mut ClosedStderr,
        ),
        ExitCode::FAILURE
    );
}

#[test]
fn size_options_read_large_numbers_exactly_and_round_up_partial_bytes() {
    // A floating-point parser could round this large whole number down by one.
    // Keep whole bytes exact, while rounding actual fractions of a byte up.
    let cli = Cli::try_parse_from([
        "lunacrypt",
        "create",
        "vault.luna",
        "--size",
        "9007199254740993 B",
        "--metadata-capacity",
        "1.2341 KB",
        "--chunk-size",
        "64KiB",
    ])
    .unwrap();
    let Command::Create {
        size,
        metadata_capacity,
        chunk_size,
        ..
    } = cli.command
    else {
        panic!("expected create command");
    };
    assert_eq!(size, 9_007_199_254_740_993);
    assert_eq!(metadata_capacity, Some(1235));
    assert_eq!(chunk_size, 65_536);
    assert_eq!(parse_size("0.1 B").unwrap(), 1);
    assert!(parse_size(".5").is_err());
    assert!(parse_size("+1 B").is_err());
}

#[test]
fn size_options_reject_numbers_too_large_to_store() {
    assert_eq!(parse_size("18446744073709551615").unwrap(), u64::MAX);
    assert_eq!(parse_size("18446744073.709551615 GB").unwrap(), u64::MAX);
    for input in [
        "18446744073709551616",
        "18446744073709551615.1",
        "18446744073709551615.5",
        "16 EiB",
    ] {
        assert!(parse_size(input).is_err(), "accepted {input}");
    }

    assert_eq!(parse_chunk_size("4294967295").unwrap(), u32::MAX);
    assert_eq!(parse_chunk_size("4294967294.1").unwrap(), u32::MAX);
    for input in ["4294967296", "4294967295.1", "4 GiB"] {
        assert!(parse_chunk_size(input).is_err(), "accepted {input}");
    }
}

#[test]
fn invalid_size_errors_do_not_repeat_unsafe_input() {
    for input in ["\u{001b}[2J", "1\u{202e}MB"] {
        let error = parse_size(input).unwrap_err();
        assert!(!error.contains(['\u{001b}', '\u{202e}']), "{error:?}");
        assert!(!error.contains(input), "{error:?}");
    }
}

#[test]
fn size_output_uses_whole_bytes_or_larger_units_with_one_decimal_place() {
    for (bytes, expected) in [
        (0, "0 B"),
        (512, "512 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (1 << 20, "1.0 MiB"),
        (1 << 50, "1.0 PiB"),
    ] {
        assert_eq!(format_size(bytes), expected);
    }
}

#[test]
fn create_uses_default_options_unless_the_user_overrides_them() {
    let cli = Cli::try_parse_from(["lunacrypt", "create", "vault.luna", "--size", "1GiB"]).unwrap();
    let Command::Create {
        cipher,
        metadata_capacity,
        fill,
        ..
    } = cli.command
    else {
        panic!("expected create command");
    };
    assert_eq!(metadata_capacity, None);
    assert_eq!(CipherId::from(cipher), CipherId::default());
    assert_eq!(cipher, CipherChoice::XChaCha20Poly1305);
    assert!(!fill);

    let cli = Cli::try_parse_from([
        "lunacrypt",
        "create",
        "vault.luna",
        "--size",
        "1GiB",
        "--metadata-capacity",
        "32MiB",
        "--fill",
    ])
    .unwrap();
    let Command::Create {
        metadata_capacity,
        fill,
        ..
    } = cli.command
    else {
        panic!("expected create command");
    };
    assert_eq!(metadata_capacity, Some(32 * 1024 * 1024));
    assert!(fill);
}

#[test]
fn create_accepts_short_and_full_encryption_names() {
    for (name, expected) in [
        ("chacha", CipherId::XChaCha20Poly1305),
        ("xchacha20-poly1305", CipherId::XChaCha20Poly1305),
        ("aes", CipherId::Aes256GcmSiv),
        ("aes-256-gcm-siv", CipherId::Aes256GcmSiv),
    ] {
        let cli = Cli::try_parse_from([
            "lunacrypt",
            "create",
            "vault.luna",
            "--size",
            "1GiB",
            "--cipher",
            name,
        ])
        .unwrap();
        let Command::Create { cipher, .. } = cli.command else {
            panic!("expected create command");
        };
        assert_eq!(CipherId::from(cipher), expected);
    }

    for name in ["aes-gcm", "aes-256-gcm", "aes-gcm-siv"] {
        assert!(
            Cli::try_parse_from([
                "lunacrypt",
                "create",
                "vault.luna",
                "--size",
                "1GiB",
                "--cipher",
                name,
            ])
            .is_err()
        );
    }
}

#[test]
fn help_succeeds_and_missing_arguments_fail_while_preserving_line_breaks() {
    for (args, code, stderr) in [
        (vec!["lunacrypt"], 2, true),
        (vec!["lunacrypt", "--help"], 0, false),
        (vec!["lunacrypt", "-h"], 0, false),
        (vec!["lunacrypt", "help", "create"], 0, false),
        (vec!["lunacrypt", "create"], 2, true),
    ] {
        let mut error = Cli::try_parse_from(args)
            .err()
            .expect("expected help or usage");
        sanitize_parse_error(&mut error);
        let rendered = error.to_string();
        // Help without a description starts directly with the usage line.
        assert!(
            rendered.starts_with("Usage: lunacrypt") || rendered.contains("\n\nUsage: lunacrypt"),
            "{rendered}"
        );
        assert!(!rendered.contains("\\u{a}"), "{rendered}");
        assert_eq!(error.exit_code(), code);
        assert_eq!(error.use_stderr(), stderr);
    }
}

#[test]
fn argument_errors_show_special_characters_as_text() {
    let malicious = "bad\n\r\t\u{001b}[2J\u{202e}value";
    let unknown_flag = format!("--{malicious}");
    for args in [
        vec!["lunacrypt", malicious],
        vec!["lunacrypt", "create", "vault.luna", &unknown_flag],
        vec!["lunacrypt", "create", "vault.luna", "--size", malicious],
        vec![
            "lunacrypt",
            "create",
            "vault.luna",
            "--size",
            "1GiB",
            "--chunk-size",
            malicious,
        ],
        vec![
            "lunacrypt",
            "create",
            "vault.luna",
            "--size",
            "1GiB",
            "--cipher",
            malicious,
        ],
    ] {
        let mut error = Cli::try_parse_from(args)
            .err()
            .expect("expected invalid input");
        sanitize_parse_error(&mut error);
        let rendered = error.to_string();
        assert!(
            rendered.contains(&terminal_safe(malicious).to_string()),
            "{rendered}"
        );
        assert!(!rendered.contains("bad\n"), "{rendered}");
        assert!(
            !rendered.contains(['\r', '\t', '\u{001b}', '\u{202e}']),
            "{rendered}"
        );
        assert!(rendered.ends_with('\n'));
        assert_eq!(error.exit_code(), 2);
        assert!(error.use_stderr());
    }
}

/// The first argument can be a renamed executable's name or a name supplied
/// by its launcher. Use a fixed program name so that argument can't insert
/// hidden controls into help or usage text.
#[test]
fn help_and_usage_always_show_lunacrypt_as_the_program_name() {
    for args in [
        vec!["bad\n\u{001b}[2J\u{202e}name"],
        vec!["bad\n\u{001b}[2J\u{202e}name", "--help"],
        vec!["bad\n\u{001b}[2J\u{202e}name", "create"],
    ] {
        let mut error = Cli::try_parse_from(args)
            .err()
            .expect("expected help or usage");
        sanitize_parse_error(&mut error);
        let rendered = error.to_string();
        assert!(rendered.contains("Usage: lunacrypt"), "{rendered}");
        assert!(!rendered.contains("bad"), "{rendered}");
        assert!(!rendered.contains(['\u{001b}', '\u{202e}']), "{rendered}");
    }
}
