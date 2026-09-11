//! Removes terminal-escape hazards from untrusted text before it is logged
//! or used in role heuristics: all C0 control characters except `\t`, `\n`,
//! `\r` and all C1 control characters are neutralized (ESC is dropped
//! entirely; the rest become spaces).

/// Sanitizes terminal-unsafe control characters out of `input`.
#[must_use]
pub fn sanitize_terminal_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\t' | '\n' | '\r' => out.push(c),
            '\x1b' => {} // OSC/CSI introducer: dropped entirely
            c if (c as u32) < 0x20 => out.push(' '),
            c if ('\u{7f}'..='\u{9f}').contains(&c) => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_esc_and_neutralizes_controls() {
        assert_eq!(sanitize_terminal_text("\x1b]0;title\x07ok"), "]0;title ok");
        assert_eq!(sanitize_terminal_text("a\u{1}\u{7f}b"), "a  b");
        assert_eq!(sanitize_terminal_text("tab\tkept"), "tab\tkept");
    }

    #[test]
    fn passes_plain_text_through() {
        assert_eq!(sanitize_terminal_text("INBOX/Sent"), "INBOX/Sent");
    }
}
