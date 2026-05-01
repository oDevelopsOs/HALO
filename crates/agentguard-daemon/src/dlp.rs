//! Data-Loss-Prevention proxy: intercepta tráfico HTTP saliente y bloquea
//! requests que contengan secretos.
//!
//! **Política de logging (obligatoria — `.windsurf/rules/04-security-logging.md`):**
//! este módulo **nunca** loggea el valor de un secreto detectado. Solo:
//! - nombre del patrón (ej: "OpenAI API Key"),
//! - URI destino (sin query string),
//! - nombre del proceso y PID (cuando se conocen).
//!
//! Sin estas restricciones el proxy DLP se convertiría en un archivo
//! central de todos los secretos que el agente ha intentado filtrar.

pub mod patterns;
pub mod proxy;

pub use patterns::{compile_defaults, CompiledPattern, DEFAULT_PATTERNS};
pub use proxy::{DlpProxy, DlpProxyHandle};
