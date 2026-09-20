use sha2::{Digest, Sha256};
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn verify_sha256(bytes: &[u8], expected: &str) -> Result<(), String> {
    let expected = expected.trim().to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Некорректный SHA-256 из release metadata".into());
    }
    if sha256_hex(bytes) != expected {
        return Err("Контрольная сумма Xray-архива не совпала".into());
    }
    Ok(())
}
pub fn parse_dgst_for_asset(dgst: &str, _asset: &str) -> Result<String, String> {
    dgst.lines()
        .find_map(|line| {
            let normalized = line.trim();
            if normalized.starts_with("SHA2-256=") || normalized.starts_with("SHA256=") {
                normalized
                    .split_once('=')
                    .map(|(_, hash)| hash.trim().to_owned())
            } else {
                None
            }
        })
        .ok_or_else(|| "Официальный .dgst не содержит SHA-256 для выбранного архива".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifies_hash() {
        let hash = sha256_hex(b"void");
        assert!(verify_sha256(b"void", &hash).is_ok());
        assert!(verify_sha256(b"changed", &hash).is_err());
    }
    #[test]
    fn parses_official_dgst_format() {
        assert_eq!(
            parse_dgst_for_asset("MD5= a\nSHA2-256= abcdef\n", "Xray-windows-64.zip").unwrap(),
            "abcdef"
        );
    }
}
