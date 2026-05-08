//! RedactionEngine — motor reutilizable de sanitización de secretos.
//!
//! Responsabilidades:
//! - Redactar texto plano con patrones regex.
//! - Redactar JSON de APIs LLM (recorriendo messages[], system, tools).
//! - Detectar endpoints LLM conocidos.
//! - Respetar allowlist de patrones "de confianza" del usuario.
//!
//! Política de logging: nunca loggea el valor del secreto, solo el nombre
//! del patrón y cuántas ocurrencias se redactaron.

use std::collections::HashSet;

use regex::Regex;

use super::patterns::{find_all_matches, replace_all, CompiledPattern};

use crate::config::RedactionStyle;

const KNOWN_LLM_HOSTS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.deepseek.com",
    "api.groq.com",
    "openrouter.ai",
    "api.together.xyz",
    "api.perplexity.ai",
    "api.cohere.ai",
    "api.x.ai",
    "api.moonshot.cn",
    "api.minimax.chat",
    "api.lingyiwanwu.com",
    "dashscope.aliyuncs.com",
];

#[derive(Debug, Clone)]
pub struct RedactionInfo {
    pub pattern_name: String,
    pub count: usize,
}

impl RedactionInfo {
    pub fn new(pattern_name: String, count: usize) -> Self {
        Self {
            pattern_name,
            count,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RedactionEngine {
    patterns: Vec<CompiledPattern>,
    style: RedactionStyle,
    llm_hosts: HashSet<String>,
    trusted: Vec<Regex>,
}

impl RedactionEngine {
    pub fn new(patterns: Vec<CompiledPattern>, style: RedactionStyle) -> Self {
        let llm_hosts: HashSet<String> = KNOWN_LLM_HOSTS.iter().map(|s| s.to_string()).collect();
        Self {
            patterns,
            style,
            llm_hosts,
            trusted: Vec::new(),
        }
    }

    pub fn with_trusted(&mut self, trusted_patterns: &[String]) -> Result<(), regex::Error> {
        self.trusted = trusted_patterns
            .iter()
            .map(|re| Regex::new(re))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    pub fn style_name(&self) -> &str {
        match self.style {
            RedactionStyle::Silent => "silent",
            RedactionStyle::Aggressive => "aggressive",
            RedactionStyle::Visible => "visible",
        }
    }

    pub fn is_llm_host(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        self.llm_hosts.contains(&host)
            || self
                .llm_hosts
                .iter()
                .any(|h| host.ends_with(&format!(".{h}")))
    }

    pub fn redact_text(&self, text: &str) -> (String, Vec<RedactionInfo>) {
        let filtered: Vec<CompiledPattern> = self
            .patterns
            .iter()
            .filter(|p| {
                !self.trusted.iter().any(|t| {
                    let combined = format!("{}|{}", t.as_str(), p.regex.as_str());
                    t.is_match(text) && regex::Regex::new(&combined).is_ok_and(|_| true)
                })
            })
            .cloned()
            .collect();

        let (redacted, events) = replace_all(&filtered, text, self.style_name());
        let infos = events
            .into_iter()
            .map(|(name, count)| RedactionInfo::new(name, count))
            .collect();
        (redacted, infos)
    }

    pub fn redact_json(&self, json: &mut serde_json::Value) -> Vec<RedactionInfo> {
        let mut all_infos = Vec::new();

        if let Some(messages) = json.get_mut("messages").and_then(|m| m.as_array_mut()) {
            for msg in messages {
                if let Some(content) = msg.get_mut("content") {
                    match content {
                        serde_json::Value::String(s) => {
                            let (redacted, infos) = self.redact_text(s);
                            if !infos.is_empty() {
                                *content = serde_json::Value::String(redacted);
                                all_infos.extend(infos);
                            }
                        }
                        serde_json::Value::Array(parts) => {
                            for part in parts {
                                if let Some(text) = part
                                    .get_mut("text")
                                    .and_then(|t| t.as_str())
                                    .map(|s| s.to_string())
                                {
                                    let (redacted, infos) = self.redact_text(&text);
                                    if !infos.is_empty() {
                                        part["text"] = serde_json::Value::String(redacted);
                                        all_infos.extend(infos);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if let Some(system) = json
            .get_mut("system")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
        {
            let (redacted, infos) = self.redact_text(&system);
            if !infos.is_empty() {
                json["system"] = serde_json::Value::String(redacted);
                all_infos.extend(infos);
            }
        }

        for key in &["system_prompt", "instructions"] {
            if let Some(val) = json
                .get_mut(*key)
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
            {
                let (redacted, infos) = self.redact_text(&val);
                if !infos.is_empty() {
                    json[*key] = serde_json::Value::String(redacted);
                    all_infos.extend(infos);
                }
            }
        }

        if let Some(tools) = json.get_mut("tools").and_then(|t| t.as_array_mut()) {
            let text = serde_json::to_string(&tools).unwrap_or_default();
            let (redacted, infos) = self.redact_text(&text);
            if !infos.is_empty() {
                if let Ok(new_tools) = serde_json::from_str::<serde_json::Value>(&redacted) {
                    *tools = new_tools
                        .as_array()
                        .cloned()
                        .unwrap_or_else(|| tools.clone());
                }
                all_infos.extend(infos);
            }
        }

        all_infos
    }

    pub fn matches_any(&self, text: &str) -> Option<(String, usize)> {
        let matches = find_all_matches(&self.patterns, text);
        matches
            .into_iter()
            .next()
            .map(|(name, count)| (name.to_string(), count))
    }
}

#[cfg(test)]
mod tests {
    use super::super::patterns::compile_defaults;
    use super::*;

    fn test_engine() -> RedactionEngine {
        let patterns = compile_defaults().expect("defaults");
        RedactionEngine::new(patterns, RedactionStyle::Visible)
    }

    #[test]
    fn redact_text_single_secret() {
        let engine = test_engine();
        let body = "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN";
        let (redacted, infos) = engine.redact_text(body);
        assert!(redacted.contains("[AGENTGUARD: OpenAI API Key REDACTED]"));
        assert!(!redacted.contains("sk-abcdefghi"));
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].pattern_name, "OpenAI API Key");
        assert_eq!(infos[0].count, 1);
    }

    #[test]
    fn redact_text_no_secrets() {
        let engine = test_engine();
        let body = "Hello world, nothing here";
        let (redacted, infos) = engine.redact_text(body);
        assert_eq!(redacted, body);
        assert!(infos.is_empty());
    }

    #[test]
    fn redact_json_openai_chat_format() {
        let engine = test_engine();
        let mut json: serde_json::Value = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant."
                },
                {
                    "role": "user",
                    "content": "Use this key: sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"
                }
            ]
        });
        let infos = engine.redact_json(&mut json);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].pattern_name, "OpenAI API Key");
        let user_content = json["messages"][1]["content"].as_str().unwrap();
        assert!(user_content.contains("[AGENTGUARD: OpenAI API Key REDACTED]"));
        assert!(!user_content.contains("sk-abcdefghi"));
    }

    #[test]
    fn redact_json_system_prompt() {
        let engine = test_engine();
        let mut json: serde_json::Value = serde_json::json!({
            "system": "Your token is ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let infos = engine.redact_json(&mut json);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].pattern_name, "GitHub Personal Token");
        assert!(json["system"].as_str().unwrap().contains("[AGENTGUARD:"));
    }

    #[test]
    fn is_llm_host_detects_known_endpoints() {
        let engine = test_engine();
        assert!(engine.is_llm_host("api.openai.com"));
        assert!(engine.is_llm_host("api.anthropic.com"));
        assert!(!engine.is_llm_host("google.com"));
        assert!(!engine.is_llm_host("example.com"));
    }

    #[test]
    fn redact_text_silent_style() {
        let patterns = compile_defaults().expect("defaults");
        let engine = RedactionEngine::new(patterns, RedactionStyle::Silent);
        let body = "key: sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN";
        let (redacted, _) = engine.redact_text(body);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("AGENTGUARD:"));
    }

    #[test]
    fn redact_text_aggressive_style() {
        let patterns = compile_defaults().expect("defaults");
        let engine = RedactionEngine::new(patterns, RedactionStyle::Aggressive);
        let body = "key: sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN";
        let (redacted, _) = engine.redact_text(body);
        assert!(redacted.contains("[SECRET REMOVED - OpenAI API Key]"));
    }

    #[test]
    fn clean_json_no_changes() {
        let engine = test_engine();
        let original = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "What is Rust?"}]
        });
        let mut json = original.clone();
        let infos = engine.redact_json(&mut json);
        assert!(infos.is_empty());
        assert_eq!(json, original);
    }
}
