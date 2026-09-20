pub fn redact(input: &str, secrets: &[String]) -> String {
    secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .fold(input.to_owned(), |value, secret| {
            value.replace(secret, "[REDACTED]")
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removes_secrets_from_diagnostics() {
        let raw = "uuid=11111111-1111-1111-1111-111111111111 token=private-token";
        let safe = redact(
            raw,
            &[
                "11111111-1111-1111-1111-111111111111".into(),
                "private-token".into(),
            ],
        );
        assert!(!safe.contains("private-token"));
        assert!(!safe.contains("11111111"));
    }
}
