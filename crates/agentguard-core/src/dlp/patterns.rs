//! Patrones DLP built-in y helpers de compilación.
//!
//! Los patrones se eligieron por especificidad: preferimos prefijos
//! distintivos (`sk-`, `ghp_`, `AKIA`, `AIza`...) a heurísticas genéricas
//! para minimizar falsos positivos. Los patrones del usuario (custom) se
//! añaden sobre estos.

use regex::Regex;
use thiserror::Error;

/// Catálogo de secretos conocidos.
pub const DEFAULT_PATTERNS: &[(&str, &str)] = &[
    ("OpenAI API Key", r"sk-[A-Za-z0-9]{48,}"),
    ("OpenAI Project Key", r"sk-proj-[A-Za-z0-9\-_]{40,}"),
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9\-_]{40,}"),
    ("GitHub Personal Token", r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub OAuth Token", r"gho_[A-Za-z0-9]{36}"),
    ("GitHub App Token", r"ghs_[A-Za-z0-9]{36}"),
    ("GitHub Fine-Grained Token", r"github_pat_[A-Za-z0-9_]{40,}"),
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Stripe Live Secret Key", r"sk_live_[0-9A-Za-z]{20,}"),
    ("Stripe Test Secret Key", r"sk_test_[0-9A-Za-z]{20,}"),
    ("Slack Bot Token", r"xoxb-[0-9A-Za-z\-]{20,}"),
    ("Slack User Token", r"xoxp-[0-9A-Za-z\-]{20,}"),
    (
        "Private Key Block",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----",
    ),
];

/// Patrón DLP compilado listo para escanear contenido.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
}

/// Errores al compilar patrones.
#[derive(Debug, Error)]
pub enum PatternError {
    #[error("invalid regex for pattern {name:?}")]
    Invalid {
        name: String,
        #[source]
        source: regex::Error,
    },
}

/// Compila `DEFAULT_PATTERNS`.
pub fn compile_defaults() -> Result<Vec<CompiledPattern>, PatternError> {
    DEFAULT_PATTERNS
        .iter()
        .map(|(name, re)| {
            Regex::new(re)
                .map(|regex| CompiledPattern {
                    name: (*name).to_string(),
                    regex,
                })
                .map_err(|source| PatternError::Invalid {
                    name: (*name).to_string(),
                    source,
                })
        })
        .collect()
}

/// Compila una lista de patrones custom.
pub fn compile_custom(custom: &[(String, String)]) -> Result<Vec<CompiledPattern>, PatternError> {
    custom
        .iter()
        .map(|(name, re)| {
            Regex::new(re)
                .map(|regex| CompiledPattern {
                    name: name.clone(),
                    regex,
                })
                .map_err(|source| PatternError::Invalid {
                    name: name.clone(),
                    source,
                })
        })
        .collect()
}

/// Compila defaults + custom.
pub fn compile_all(custom: &[(String, String)]) -> Result<Vec<CompiledPattern>, PatternError> {
    let mut all = compile_defaults()?;
    all.extend(compile_custom(custom)?);
    Ok(all)
}

/// Busca el primer patrón que haga match. Devuelve solo el nombre.
pub fn first_match<'a>(patterns: &'a [CompiledPattern], haystack: &str) -> Option<&'a str> {
    patterns
        .iter()
        .find(|p| p.regex.is_match(haystack))
        .map(|p| p.name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_patterns_all_compile() {
        let compiled = compile_defaults().expect("defaults compile");
        assert_eq!(compiled.len(), DEFAULT_PATTERNS.len());
    }

    #[test]
    fn detects_openai_key() {
        let p = compile_defaults().expect("defaults");
        let body = "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN";
        assert_eq!(first_match(&p, body), Some("OpenAI API Key"));
    }

    #[test]
    fn detects_anthropic_key() {
        let p = compile_defaults().expect("defaults");
        let body = "api_key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890";
        assert_eq!(first_match(&p, body), Some("Anthropic API Key"));
    }

    #[test]
    fn detects_github_token_variants() {
        let p = compile_defaults().expect("defaults");
        let classic = format!("token={}", "ghp_".to_string() + &"a".repeat(36));
        let oauth = format!("token={}", "gho_".to_string() + &"b".repeat(36));
        assert_eq!(first_match(&p, &classic), Some("GitHub Personal Token"));
        assert_eq!(first_match(&p, &oauth), Some("GitHub OAuth Token"));
    }

    #[test]
    fn detects_aws_access_key_id() {
        let p = compile_defaults().expect("defaults");
        let body = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        assert_eq!(first_match(&p, body), Some("AWS Access Key ID"));
    }

    #[test]
    fn detects_private_key_header() {
        let p = compile_defaults().expect("defaults");
        let body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC...";
        assert_eq!(first_match(&p, body), Some("Private Key Block"));
    }

    #[test]
    fn clean_body_has_no_match() {
        let p = compile_defaults().expect("defaults");
        let body = "Hello world, just a perfectly normal request body.";
        assert_eq!(first_match(&p, body), None);
    }

    #[test]
    fn custom_patterns_compile_and_match() {
        let custom = vec![(
            "Internal Token".to_string(),
            r"mycompany-[a-zA-Z0-9]{32}".to_string(),
        )];
        let all = compile_all(&custom).expect("compile all");
        let body = format!("X-Token: mycompany-{}", "z".repeat(32));
        assert_eq!(first_match(&all, &body), Some("Internal Token"));
    }

    #[test]
    fn bad_custom_regex_returns_error() {
        let custom = vec![("Broken".to_string(), "[unclosed".to_string())];
        let err = compile_custom(&custom).unwrap_err();
        match err {
            PatternError::Invalid { name, .. } => assert_eq!(name, "Broken"),
        }
    }

    #[test]
    fn first_match_short_circuits_on_first() {
        let custom = vec![
            ("A".to_string(), r"abc".to_string()),
            ("B".to_string(), r"abc".to_string()),
        ];
        let all = compile_custom(&custom).expect("compile");
        assert_eq!(first_match(&all, "abc"), Some("A"));
    }
}
