pub fn sh_quote(input: &str) -> String {
    if input.is_empty() {
        return "''".to_string();
    }

    if !input.contains('\'') {
        return format!("'{input}'");
    }

    let mut out = String::with_capacity(input.len() + 2);
    out.push('\'');
    for ch in input.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_empty() {
        assert_eq!(sh_quote(""), "''");
    }

    #[test]
    fn sh_quote_no_single_quotes() {
        assert_eq!(sh_quote("abc def"), "'abc def'");
    }

    #[test]
    fn sh_quote_with_single_quote() {
        assert_eq!(sh_quote("a'b"), "'a'\"'\"'b'");
    }
}
