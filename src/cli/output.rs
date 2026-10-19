use std::{
    collections::BTreeMap,
    fmt::{self, Display, Write as _},
    io,
    path::Path,
};

use lunacrypt::FileInfo;
use zeroize::Zeroize;

use super::format_size;

#[derive(Default)]
pub(super) struct TreeNode {
    children: BTreeMap<String, TreeNode>,
    size: Option<u64>,
}

impl Drop for TreeNode {
    fn drop(&mut self) {
        // The map orders entries by name. Erasing a name while it's still a key
        // would change that ordering, so remove each entry before wiping it.
        for (mut name, _) in std::mem::take(&mut self.children) {
            name.zeroize();
        }
        self.size.zeroize();
    }
}

pub(super) fn build_tree(files: &[FileInfo]) -> TreeNode {
    let mut root = TreeNode::default();
    for file in files {
        let mut node = &mut root;
        for segment in file.path.split('/') {
            if !node.children.contains_key(segment) {
                node.children
                    .insert(segment.to_string(), TreeNode::default());
            }
            node = node
                .children
                .get_mut(segment)
                .expect("inserted tree component");
        }
        if !file.is_directory {
            node.size = Some(file.size);
        }
    }
    root
}

pub(super) fn write_tree(
    output: &mut impl io::Write,
    node: &TreeNode,
    depth: usize,
) -> io::Result<()> {
    let mut names: Vec<&String> = node.children.keys().collect();
    names.sort_by(|left, right| {
        let left_directory = node.children[*left].size.is_none();
        let right_directory = node.children[*right].size.is_none();
        right_directory
            .cmp(&left_directory)
            .then_with(|| left.cmp(right))
    });
    let indent = "  ".repeat(depth);
    for name in names {
        let child = &node.children[name];
        match child.size {
            Some(size) => writeln!(
                output,
                "{indent}{}\t{}",
                terminal_safe(name),
                format_size(size)
            )?,
            None => writeln!(output, "{indent}{}/", terminal_safe(name))?,
        }
        write_tree(output, child, depth + 1)?;
    }
    Ok(())
}

fn is_unsafe_terminal_character(character: char) -> bool {
    // A name can contain more than a newline: terminal controls can clear the
    // screen, and direction markers can make the displayed name misleading.
    // Show these characters as escapes so they remain visible text.
    matches!(character as u32, 0x0000..=0x001f | 0x007f..=0x009f)
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

struct TerminalSafe<T>(T);

impl<T: Display> Display for TerminalSafe<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(EscapedWriter(formatter), "{}", self.0)
    }
}

// Display can write text in several pieces. Escape each piece as it arrives
// so filenames, locations, and errors don't need another temporary String copy.
struct EscapedWriter<'a, 'b>(&'a mut fmt::Formatter<'b>);

impl fmt::Write for EscapedWriter<'_, '_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut start = 0;
        for (index, character) in text.char_indices() {
            if is_unsafe_terminal_character(character) {
                self.0.write_str(&text[start..index])?;
                write!(self.0, "\\u{{{:x}}}", character as u32)?;
                start = index + character.len_utf8();
            }
        }
        self.0.write_str(&text[start..])
    }
}

pub(super) fn terminal_safe(text: &str) -> impl Display + '_ {
    TerminalSafe(text)
}

pub(super) fn terminal_safe_path(path: &Path) -> impl Display + '_ {
    TerminalSafe(path.display())
}

pub(super) fn terminal_safe_display(value: &impl Display) -> impl Display + '_ {
    TerminalSafe(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_list_shows_files_inside_folders_with_their_sizes() {
        let files = vec![
            FileInfo {
                path: "docs".to_string(),
                size: 0,
                is_directory: true,
            },
            FileInfo {
                path: "docs/a.txt".to_string(),
                size: 3,
                is_directory: false,
            },
        ];
        let tree = build_tree(&files);
        assert_eq!(tree.children["docs"].children["a.txt"].size, Some(3));
        let mut output = Vec::new();
        write_tree(&mut output, &tree, 0).unwrap();
        assert_eq!(output, b"docs/\n  a.txt\t3 B\n");
    }

    #[test]
    fn file_list_returns_an_error_when_it_cannot_be_written() {
        struct FailingWriter(io::ErrorKind);
        impl io::Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(self.0.into())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let tree = build_tree(&[FileInfo {
            path: "file.txt".to_string(),
            size: 1,
            is_directory: false,
        }]);
        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::PermissionDenied] {
            assert_eq!(
                write_tree(&mut FailingWriter(kind), &tree, 0)
                    .unwrap_err()
                    .kind(),
                kind
            );
        }
    }

    #[test]
    fn printed_text_makes_hidden_and_direction_changing_characters_visible() {
        let unsafe_text = "ok\n\u{001b}\u{0085}\u{061c}\u{202e}\u{2066}bad";
        let escaped = terminal_safe(unsafe_text).to_string();
        assert_eq!(
            escaped,
            "ok\\u{a}\\u{1b}\\u{85}\\u{61c}\\u{202e}\\u{2066}bad"
        );
        assert!(!escaped.chars().any(is_unsafe_terminal_character));
    }

    #[test]
    fn printed_file_paths_make_special_characters_visible() {
        let escaped = terminal_safe_path(Path::new("safe\u{202e}name\n.txt")).to_string();
        assert_eq!(escaped, "safe\\u{202e}name\\u{a}.txt");
    }

    #[test]
    fn printed_values_make_special_characters_visible_and_report_formatting_failures() {
        struct Fragments;
        impl Display for Fragments {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("α\n")?;
                formatter.write_char('\u{202e}')?;
                formatter.write_str("β")
            }
        }
        assert_eq!(
            terminal_safe_display(&Fragments).to_string(),
            "α\\u{a}\\u{202e}β"
        );

        struct Failure;
        impl Display for Failure {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                Err(fmt::Error)
            }
        }
        assert!(write!(String::new(), "{}", terminal_safe_display(&Failure)).is_err());
    }
}
