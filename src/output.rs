//! Output boundaries for controller-supplied data.
use serde_json::{Value, json};

/// Visible escapes prevent controller strings from controlling the terminal.
pub fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Escape remaining Unicode terminal controls in serialized JSON. JSON already
/// escapes C0 string controls; preserving its layout newlines keeps pretty output
/// readable. Escaping after serialization avoids changing/colliding object keys.
pub fn pretty_json(value: &Value) -> serde_json::Result<String> {
    let serialized = serde_json::to_string_pretty(value)?;
    let mut safe = String::with_capacity(serialized.len());
    for c in serialized.chars() {
        if (c.is_control() && c != '\n' && c != '\r' && c != '\t')
            || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            use std::fmt::Write;
            write!(&mut safe, "\\u{:04x}", c as u32).expect("writing a string cannot fail");
        } else {
            safe.push(c);
        }
    }
    Ok(safe)
}

/// Spreadsheet profile: make formula-shaped cells text, including prefixes
/// concealed behind whitespace. CSV quoting alone does not do this.
pub fn spreadsheet_safe(value: &str) -> String {
    let safe = terminal_safe(value);
    if value.trim_start().starts_with(['=', '+', '-', '@']) || value.starts_with(['\t', '\r', '\n'])
    {
        format!("'{safe}")
    } else {
        safe
    }
}

pub fn rows(value: &Value) -> Option<&Vec<Value>> {
    value
        .as_array()
        .or_else(|| value.get("data").and_then(Value::as_array))
}

/// Capture source counts before command-specific filters and limits. Array
/// responses gain an envelope so metadata survives machine serialization.
pub fn capture_collection(value: &mut Value) {
    if value.is_array() {
        *value = json!({"data": value.take()});
    }
    let Some(count) = rows(value).map(Vec::len) else {
        return;
    };
    if value.get("_unifictl").is_some() {
        return;
    }
    let total = value
        .get("total_element_count")
        .or_else(|| value.get("totalCount"))
        .and_then(Value::as_u64);
    value["_unifictl"] = json!({"collection": {
        "source_count": count,
        "total_available": total,
        "returned_count": count,
        "truncated": false,
        "inventory_complete": if total == Some(count as u64) { "complete" } else { "unknown" },
    }});
}

pub fn finish_collection(value: &mut Value) {
    capture_collection(value);
    let Some(count) = rows(value).map(Vec::len) else {
        return;
    };
    let source = value["_unifictl"]["collection"]["source_count"]
        .as_u64()
        .unwrap_or(count as u64);
    let total = value["_unifictl"]["collection"]["total_available"].as_u64();
    let already_truncated = value["_unifictl"]["collection"]["truncated"]
        .as_bool()
        .unwrap_or(false);
    let truncated =
        already_truncated || count < source as usize || total.is_some_and(|n| n > count as u64);
    value["_unifictl"]["collection"]["returned_count"] = json!(count);
    value["_unifictl"]["collection"]["truncated"] = json!(truncated);
    value["_unifictl"]["collection"]["inventory_complete"] = json!(if truncated {
        "incomplete"
    } else if total == Some(count as u64) {
        "complete"
    } else {
        "unknown"
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_and_spreadsheet_data_are_not_interpreted() {
        assert_eq!(
            terminal_safe("a\x1b[2J\n\u{202e}"),
            "a\\u{1b}[2J\\n\\u{202e}"
        );
        assert_eq!(spreadsheet_safe(" \t=1+1"), "' \\t=1+1");
        assert_eq!(spreadsheet_safe("ordinary"), "ordinary");
        assert_eq!(spreadsheet_safe("-42"), "'-42");
    }
    #[test]
    fn nested_pretty_json_is_terminal_safe_without_flattening_layout() {
        let value = json!({"unsafe\u{202e}": [{"name":"value\u{2066}\u{202e}\u{1b}"}]});
        let rendered = pretty_json(&value).unwrap();
        assert!(!rendered.contains(['\u{202e}', '\u{2066}', '\u{1b}']));
        assert!(rendered.contains('\n'));
        assert!(rendered.contains("\\u202e"));
        assert_eq!(serde_json::from_str::<Value>(&rendered).unwrap(), value);
    }
    #[test]
    fn truncation_and_unknown_totals_survive_rendering() {
        let mut data = json!([{"id":1},{"id":2}]);
        capture_collection(&mut data);
        data["data"].as_array_mut().unwrap().truncate(1);
        finish_collection(&mut data);
        assert_eq!(data["_unifictl"]["collection"]["source_count"], 2);
        assert_eq!(
            data["_unifictl"]["collection"]["inventory_complete"],
            "incomplete"
        );
        let mut unknown = json!({"data":[]});
        finish_collection(&mut unknown);
        assert_eq!(
            unknown["_unifictl"]["collection"]["inventory_complete"],
            "unknown"
        );
    }
}
