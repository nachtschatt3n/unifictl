//! Presentation boundaries for untrusted controller text.

fn terminal_control(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

pub fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if terminal_control(c) {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Escape Unicode terminal controls after serialization to preserve object keys
/// and JSON values. Keep the serializer's formatting newlines readable.
pub fn pretty_json(value: &serde_json::Value) -> serde_json::Result<String> {
    let serialized = serde_json::to_string_pretty(value)?;
    let mut safe = String::with_capacity(serialized.len());
    for c in serialized.chars() {
        if terminal_control(c) && !matches!(c, '\n' | '\r' | '\t') {
            use std::fmt::Write;
            write!(&mut safe, "\\u{:04x}", c as u32).expect("writing a string cannot fail");
        } else {
            safe.push(c);
        }
    }
    Ok(safe)
}

/// CSV quoting alone does not prevent spreadsheet formula evaluation.
pub fn spreadsheet_safe(value: &str) -> String {
    let safe = terminal_safe(value);
    if value.trim_start().starts_with(['=', '+', '-', '@']) || value.starts_with(['\t', '\r', '\n'])
    {
        format!("'{safe}")
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_bidi_marks_are_visible_text() {
        let value = "a\x1b[2J\n\u{85}\u{061c}\u{200f}\u{202e}\u{2066}";
        assert!(!terminal_safe(value).chars().any(terminal_control));
        assert!(terminal_safe(value).contains("\\u{1b}"));
    }

    #[test]
    fn pretty_json_preserves_nested_values_and_keys() {
        let value = serde_json::json!({"key\u{202e}":[{"text":"a\u{85}\u{200f}\u{2066}"}],"key\\u202e":"distinct"});
        let rendered = pretty_json(&value).unwrap();
        assert!(!rendered.chars().any(|c| terminal_control(c) && c != '\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rendered).unwrap(),
            value
        );
    }

    #[test]
    fn formula_prefixes_including_whitespace_are_text() {
        for value in [
            "=1+1", "+1", "-42", "@SUM(A1)", " \t=1", "\rhidden", "\ttext", "\ntext",
        ] {
            assert!(spreadsheet_safe(value).starts_with('\''), "{value:?}");
        }
        assert_eq!(spreadsheet_safe("ordinary"), "ordinary");
    }
}
