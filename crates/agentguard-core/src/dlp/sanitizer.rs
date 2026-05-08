//! PromptSanitizer — sanitizador de prompts a APIs LLM.
//!
//! Intercepta requests HTTP a endpoints LLM conocidos, parsea el body como JSON
//! y redacta cualquier secreto encontrado en los campos de texto (messages, system,
//! tools, etc.). El request se reenvía con los secretos redactados.
//!
//! Política de logging: nunca loggea el valor del secreto. Solo:
//! - nombre del patrón
//! - destino (hostname)
//! - proceso emisor
//! - cuántas ocurrencias se redactaron

use bytes::Bytes;
use serde_json;
use tokio::sync::broadcast;

use super::redaction::{RedactionEngine, RedactionInfo};
use crate::events::SecurityEvent;

#[derive(Clone)]
pub struct PromptSanitizer {
    engine: RedactionEngine,
    events: Option<broadcast::Sender<SecurityEvent>>,
}

impl PromptSanitizer {
    pub fn new(engine: RedactionEngine, events: Option<broadcast::Sender<SecurityEvent>>) -> Self {
        Self { engine, events }
    }

    pub fn engine(&self) -> &RedactionEngine {
        &self.engine
    }

    pub fn is_llm_request(&self, host: &str) -> bool {
        self.engine.is_llm_host(host)
    }

    /// Procesa un body HTTP. Si es JSON y el destino es un LLM, redacta secretos.
    /// Devuelve (body_posiblemente_modificado, lista_de_info_de_redacción).
    pub fn process_body(
        &self,
        body: &[u8],
        destination_host: &str,
        source_process: &str,
        pid: u32,
    ) -> (Bytes, Vec<RedactionInfo>) {
        if body.is_empty() || !self.engine.is_llm_host(destination_host) {
            return (Bytes::copy_from_slice(body), Vec::new());
        }

        let body_text = std::str::from_utf8(body).unwrap_or("");
        let mut json: serde_json::Value = match serde_json::from_str(body_text) {
            Ok(v) => v,
            Err(_) => {
                let (redacted, infos) = self.engine.redact_text(body_text);
                if infos.is_empty() {
                    return (Bytes::copy_from_slice(body), Vec::new());
                }
                self.emit_redaction_events(&infos, destination_host, source_process, pid);
                return (Bytes::from(redacted.into_bytes()), infos);
            }
        };

        let infos = self.engine.redact_json(&mut json);

        if infos.is_empty() {
            return (Bytes::copy_from_slice(body), Vec::new());
        }

        self.emit_redaction_events(&infos, destination_host, source_process, pid);

        let sanitized_body = serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec());
        (Bytes::from(sanitized_body), infos)
    }

    /// Procesa un chunk de datos (para MITM streaming). Mejor-esfuerzo.
    pub fn process_chunk(
        &self,
        chunk: &[u8],
        destination_host: &str,
        source_process: &str,
        pid: u32,
    ) -> (Bytes, Vec<RedactionInfo>) {
        let text = String::from_utf8_lossy(chunk);
        let (redacted, infos) = self.engine.redact_text(&text);

        if infos.is_empty() {
            return (Bytes::copy_from_slice(chunk), Vec::new());
        }

        self.emit_redaction_events(&infos, destination_host, source_process, pid);
        (Bytes::from(redacted.into_bytes()), infos)
    }

    fn emit_redaction_events(
        &self,
        infos: &[RedactionInfo],
        destination: &str,
        process: &str,
        pid: u32,
    ) {
        if let Some(ref tx) = self.events {
            let timestamp = now_ts();
            for info in infos {
                let _ = tx.send(SecurityEvent::DlpRedaction {
                    pattern_name: info.pattern_name.clone(),
                    destination: destination.to_string(),
                    process: process.to_string(),
                    pid,
                    redaction_count: info.count as u32,
                    timestamp,
                });
            }
        }
    }
}

fn now_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::super::patterns::compile_defaults;
    use super::*;
    use crate::config::RedactionStyle;

    fn test_sanitizer() -> PromptSanitizer {
        let patterns = compile_defaults().expect("defaults");
        let engine = RedactionEngine::new(patterns, RedactionStyle::Visible);
        PromptSanitizer::new(engine, None)
    }

    #[test]
    fn processes_openai_chat_json() {
        let sanitizer = test_sanitizer();
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "Use key sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN please"}
            ]
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let (result, infos) = sanitizer.process_body(&body_bytes, "api.openai.com", "cursor", 1234);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].pattern_name, "OpenAI API Key");
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("[AGENTGUARD: OpenAI API Key REDACTED]"));
        assert!(!result_str.contains("sk-abcdefghi"));
    }

    #[test]
    fn ignores_non_llm_endpoints() {
        let sanitizer = test_sanitizer();
        let body = b"Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN";
        let (result, infos) = sanitizer.process_body(body, "httpbin.org", "curl", 42);
        assert!(infos.is_empty());
        assert_eq!(&result[..], body);
    }

    #[test]
    fn process_chunk_redacts_text() {
        let sanitizer = test_sanitizer();
        let chunk = b"leaked: sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN more data";
        let (result, infos) = sanitizer.process_chunk(chunk, "api.openai.com", "windsurf", 5678);
        assert_eq!(infos.len(), 1);
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("[AGENTGUARD: OpenAI API Key REDACTED]"));
    }

    #[test]
    fn empty_body_noop() {
        let sanitizer = test_sanitizer();
        let (result, infos) = sanitizer.process_body(b"", "api.openai.com", "test", 0);
        assert!(infos.is_empty());
        assert!(result.is_empty());
    }

    #[test]
    fn non_json_body_still_redacted() {
        let sanitizer = test_sanitizer();
        let body = b"Here is my key: sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN end";
        let (result, infos) = sanitizer.process_body(body, "api.openai.com", "agent", 1);
        assert_eq!(infos.len(), 1);
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("[AGENTGUARD: OpenAI API Key REDACTED]"));
    }

    #[test]
    fn known_llm_endpoints_detected() {
        let sanitizer = test_sanitizer();
        assert!(sanitizer.is_llm_request("api.openai.com"));
        assert!(sanitizer.is_llm_request("api.anthropic.com"));
        assert!(sanitizer.is_llm_request("api.deepseek.com"));
        assert!(!sanitizer.is_llm_request("google.com"));
        assert!(!sanitizer.is_llm_request("localhost"));
    }

    #[test]
    fn clean_request_passes_untouched() {
        let sanitizer = test_sanitizer();
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "What is Rust?"}]
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let (result, infos) = sanitizer.process_body(&body_bytes, "api.openai.com", "cursor", 1);
        assert!(infos.is_empty());
        let result_val: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(result_val, body);
    }
}
