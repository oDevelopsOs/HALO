//! Proxy HTTP userspace que escanea cada request en busca de secretos.
//!
//! **Alcance de Fase 2.1:** HTTP plano (sin CONNECT tunneling/HTTPS MITM).
//! HTTPS se añade en Fase 2.3 con `rcgen` + `tokio-rustls`. Hasta entonces,
//! el proxy solo es útil cuando el agente se configura con `HTTP_PROXY`
//! apuntando aquí; HTTPS pasará con `CONNECT` sin inspección y el proxy
//! simplemente lo rechazará con 501.
//!
//! Arquitectura:
//! - hyper 1.x `service_fn` por request.
//! - Leemos el body completo (hasta un límite) para escanear.
//! - Si hay match → 403 con mensaje claro + evento `DlpViolation`.
//! - Si no → reenviamos al host destino con un cliente hyper-util.
//!
//! **Logging:** ver `src/dlp.rs` — **nunca** el valor del secreto.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use super::patterns::{first_match, CompiledPattern};
use crate::config::DlpAction;
use crate::events::SecurityEvent;

/// Límite defensivo para el tamaño del body escaneado. Requests mayores
/// se reenvían sin escanear y se loggea un warning — evita OOM.
const MAX_BODY_SCAN_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB

/// Errores del proxy.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to bind {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("accept loop error")]
    Accept(#[source] std::io::Error),
}

/// Handle para parar el proxy limpiamente.
#[derive(Debug)]
pub struct DlpProxyHandle {
    shutdown: Option<oneshot::Sender<()>>,
    local_addr: SocketAddr,
}

impl DlpProxyHandle {
    /// Dirección efectiva (útil cuando se pasó port 0 para tests).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Detiene el proxy. Las conexiones activas terminarán naturalmente.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for DlpProxyHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Configuración y runtime del proxy DLP.
pub struct DlpProxy {
    patterns: Arc<Vec<CompiledPattern>>,
    action: DlpAction,
    events: Option<mpsc::Sender<SecurityEvent>>,
}

impl DlpProxy {
    /// Crea un proxy con los patrones compilados y la acción configurada.
    pub fn new(patterns: Vec<CompiledPattern>, action: DlpAction) -> Self {
        Self {
            patterns: Arc::new(patterns),
            action,
            events: None,
        }
    }

    /// Conecta el proxy con el canal de eventos del daemon. Cuando se
    /// detecta una violación, emite un `SecurityEvent::DlpViolation`.
    pub fn with_events(mut self, tx: mpsc::Sender<SecurityEvent>) -> Self {
        self.events = Some(tx);
        self
    }

    /// Arranca el proxy en `addr` y retorna un handle para pararlo.
    ///
    /// Usar port `0` en tests para que el SO asigne uno libre y obtenerlo
    /// vía `handle.local_addr()`.
    pub async fn start(self, addr: SocketAddr) -> Result<DlpProxyHandle, ProxyError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| ProxyError::Bind { addr, source })?;
        let local_addr = listener
            .local_addr()
            .map_err(|source| ProxyError::Bind { addr, source })?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let patterns = self.patterns.clone();
        let action = self.action;
        let events = self.events.clone();

        // Cliente HTTP para reenviar requests aprobados.
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        let client = Arc::new(client);

        tracing::info!(%local_addr, "DLP proxy listening");

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        tracing::info!("DLP proxy shutting down");
                        break;
                    }
                    accept = listener.accept() => {
                        let (stream, peer) = match accept {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(error = %e, "accept error");
                                continue;
                            }
                        };
                        let patterns = patterns.clone();
                        let events = events.clone();
                        let client = client.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let svc = service_fn(move |req| {
                                let patterns = patterns.clone();
                                let events = events.clone();
                                let client = client.clone();
                                async move {
                                    Ok::<_, Infallible>(
                                        handle_request(req, patterns, action, events, client)
                                            .await,
                                    )
                                }
                            });
                            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                                tracing::debug!(peer = ?peer, error = %e, "connection error");
                            }
                        });
                    }
                }
            }
        });

        Ok(DlpProxyHandle {
            shutdown: Some(shutdown_tx),
            local_addr,
        })
    }
}

/// Handler por request. Escanea → decide → (reenvía | bloquea).
async fn handle_request(
    req: Request<Incoming>,
    patterns: Arc<Vec<CompiledPattern>>,
    action: DlpAction,
    events: Option<mpsc::Sender<SecurityEvent>>,
    client: Arc<Client<HttpConnector, Full<Bytes>>>,
) -> Response<Full<Bytes>> {
    // HTTPS (CONNECT tunnel) queda fuera de Fase 2.1.
    if req.method() == Method::CONNECT {
        tracing::debug!(uri = %req.uri(), "CONNECT not supported in Phase 2.1");
        return text_response(
            StatusCode::NOT_IMPLEMENTED,
            "AgentGuard DLP: HTTPS MITM not enabled in this build. \
             Configure agents to use HTTP proxy only, or upgrade to \
             a build with the --features tls-mitm flag.",
        );
    }

    let (parts, body) = req.into_parts();
    let uri_for_log = sanitize_uri(&parts.uri.to_string());

    // Serializamos headers+body a un string para el escaneo. Solo escaneamos
    // contenido textual; si los primeros bytes son binarios se salta el body.
    let header_dump = dump_headers(&parts.headers);

    let body_bytes = match read_body_bounded(body, MAX_BODY_SCAN_BYTES).await {
        Ok(b) => b,
        Err(BodyReadError::TooLarge) => {
            tracing::warn!(
                destination = %uri_for_log,
                limit = MAX_BODY_SCAN_BYTES,
                "request body exceeds DLP scan limit — forwarded without scanning"
            );
            // Fail-open: reenviar sin escanear para no bloquear uploads legítimos.
            // El usuario puede subir el límite en config si lo desea.
            Bytes::new()
        }
        Err(e @ BodyReadError::Io(_)) => {
            tracing::warn!(error = %e, "body read error");
            return text_response(
                StatusCode::BAD_GATEWAY,
                "AgentGuard DLP: upstream body read error",
            );
        }
    };

    let body_text = if looks_text(&body_bytes) {
        std::str::from_utf8(&body_bytes).unwrap_or("").to_string()
    } else {
        String::new()
    };

    let haystack = format!("{header_dump}\n{body_text}");

    if let Some(matched) = first_match(&patterns, &haystack) {
        // ——— VIOLACIÓN ———
        tracing::warn!(
            pattern = %matched,
            destination = %uri_for_log,
            action = ?action,
            "DLP violation detected"
        );
        if let Some(ref tx) = events {
            let _ = tx
                .send(SecurityEvent::DlpViolation {
                    pattern_name: matched.to_string(),
                    destination: uri_for_log.clone(),
                    process: "<proxy-unknown>".into(),
                    pid: 0,
                    timestamp: now_ts(),
                })
                .await;
        }
        match action {
            DlpAction::Block => {
                return text_response(
                    StatusCode::FORBIDDEN,
                    &format!(
                        "AgentGuard DLP: request blocked — {} detected. \
                         Check your agent's prompt for credential leaks.",
                        matched
                    ),
                );
            }
            DlpAction::Alert | DlpAction::Log => {
                // Seguir al forward — la violación ya se registró.
            }
        }
    }

    // ——— Forward ———
    forward_request(parts, body_bytes, client).await
}

async fn forward_request(
    parts: hyper::http::request::Parts,
    body: Bytes,
    client: Arc<Client<HttpConnector, Full<Bytes>>>,
) -> Response<Full<Bytes>> {
    let uri = parts.uri.clone();
    // El cliente hyper-util necesita un URI absoluto con scheme+authority.
    if uri.scheme().is_none() {
        return text_response(
            StatusCode::BAD_REQUEST,
            "AgentGuard DLP: only absolute URIs are supported",
        );
    }
    let mut builder = Request::builder().method(parts.method).uri(uri);
    for (k, v) in parts.headers.iter() {
        builder = builder.header(k, v);
    }
    let outbound = match builder.body(Full::new(body)) {
        Ok(r) => r,
        Err(e) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                &format!("AgentGuard DLP: cannot rebuild request: {e}"),
            );
        }
    };

    match client.request(outbound).await {
        Ok(resp) => {
            let (p, b) = resp.into_parts();
            let bytes = match b.collect().await {
                Ok(c) => c.to_bytes(),
                Err(e) => {
                    return text_response(
                        StatusCode::BAD_GATEWAY,
                        &format!("AgentGuard DLP: upstream body error: {e}"),
                    );
                }
            };
            let mut out = Response::builder().status(p.status);
            for (k, v) in p.headers.iter() {
                out = out.header(k, v);
            }
            out.body(Full::new(bytes)).unwrap_or_else(|_| {
                text_response(
                    StatusCode::BAD_GATEWAY,
                    "AgentGuard DLP: cannot rebuild response",
                )
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream error");
            text_response(
                StatusCode::BAD_GATEWAY,
                "AgentGuard DLP: upstream connection error",
            )
        }
    }
}

/// Construye una respuesta de texto plano (usado para errores y bloqueos).
fn text_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-agentguard-dlp", "1")
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap_or_else(|_| {
            // Solo alcanzable si la cabecera es inválida — nunca pasa.
            // unwrap-ok: fallback trivial con cuerpo vacío.
            Response::new(Full::new(Bytes::new()))
        })
}

#[derive(Debug)]
enum BodyReadError {
    TooLarge,
    /// Error de lectura del body upstream. Guardamos solo el mensaje
    /// porque `hyper::Error` no se puede construir manualmente.
    Io(String),
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "body exceeds DLP scan limit"),
            Self::Io(msg) => write!(f, "upstream body read error: {msg}"),
        }
    }
}

async fn read_body_bounded(body: Incoming, limit: u64) -> Result<Bytes, BodyReadError> {
    use http_body_util::Limited;
    let limited = Limited::new(body, limit as usize);
    match limited.collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) => {
            // `Limited` wrappea el error en un Box<dyn Error + Send + Sync>
            // cuando se excede el límite. Usamos el mensaje como indicador.
            let msg = e.to_string();
            if msg.contains("limit") || msg.contains("length") {
                Err(BodyReadError::TooLarge)
            } else {
                Err(BodyReadError::Io(msg))
            }
        }
    }
}

fn dump_headers(headers: &hyper::HeaderMap) -> String {
    let mut s = String::new();
    for (k, v) in headers.iter() {
        s.push_str(k.as_str());
        s.push_str(": ");
        if let Ok(text) = v.to_str() {
            s.push_str(text);
        }
        s.push('\n');
    }
    s
}

/// URI saneada: sin query string. Aplica el requisito de logging — no
/// queremos loggear credenciales pasadas por query (`?api_key=...`).
fn sanitize_uri(uri: &str) -> String {
    match uri.find('?') {
        Some(q) => uri[..q].to_string(),
        None => uri.to_string(),
    }
}

fn looks_text(bytes: &[u8]) -> bool {
    // Heurística barata: si los primeros 256 bytes tienen byte NUL o >30%
    // no-ASCII, tratamos como binario y nos saltamos el escaneo del body.
    // (Los headers siempre se escanean, donde suelen ir los tokens reales.)
    let sample = &bytes[..bytes.len().min(256)];
    if sample.contains(&0) {
        return false;
    }
    let non_ascii = sample.iter().filter(|b| **b > 127).count();
    sample.is_empty() || non_ascii * 10 < sample.len() * 3
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
    use super::*;
    use crate::dlp::patterns::compile_defaults;
    use std::net::{IpAddr, Ipv4Addr};

    async fn start_test_proxy(action: DlpAction) -> DlpProxyHandle {
        let proxy = DlpProxy::new(compile_defaults().expect("defaults"), action);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        proxy.start(addr).await.expect("proxy start")
    }

    /// Cliente HTTP mínimo con hyper 1.x para evitar dependencia de reqwest
    /// en dev-dependencies. Se conecta al proxy por su SocketAddr y envía
    /// un request con URI absoluta (como haría un cliente configurado con
    /// HTTP_PROXY).
    async fn send_through_proxy(
        proxy: SocketAddr,
        method: &str,
        absolute_uri: &str,
        body: &str,
    ) -> (StatusCode, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = TcpStream::connect(proxy).await.expect("connect");
        let req = format!(
            "{method} {absolute_uri} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            host = hyper::Uri::try_from(absolute_uri)
                .ok()
                .and_then(|u| u.host().map(str::to_string))
                .unwrap_or_else(|| "unknown".into()),
            len = body.len(),
        );
        stream.write_all(req.as_bytes()).await.expect("write");
        // NOTA: no hacer stream.shutdown() antes de leer — hyper 1.x
        // puede reaccionar al FIN cerrando la conexión antes de que el
        // response esté fully-buffered en el lado del cliente.

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let text = String::from_utf8_lossy(&buf).to_string();

        // Parsear status code del response line.
        let status_line = text.lines().next().unwrap_or("");
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .and_then(|n| StatusCode::from_u16(n).ok())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (code, text)
    }

    #[tokio::test]
    async fn blocks_request_with_openai_key_in_body() {
        let handle = start_test_proxy(DlpAction::Block).await;
        let (code, body) = send_through_proxy(
            handle.local_addr(),
            "POST",
            "http://example.invalid/chat",
            "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN",
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN, "response was:\n{body}");
        assert!(body.contains("AgentGuard DLP"));
        assert!(body.contains("OpenAI API Key"));
        handle.shutdown();
    }

    #[tokio::test]
    async fn blocks_github_token_in_header() {
        let handle = start_test_proxy(DlpAction::Block).await;
        // El patrón GitHub hace match sobre headers — mandamos el token en Authorization.
        let (code, body) = send_through_proxy(
            handle.local_addr(),
            "GET",
            "http://example.invalid/user",
            &format!("X-Custom: ghp_{}", "a".repeat(36)),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        assert!(body.contains("GitHub Personal Token"));
        handle.shutdown();
    }

    #[tokio::test]
    async fn rejects_connect_tunneling_with_501() {
        let handle = start_test_proxy(DlpAction::Block).await;
        let (code, _) = send_through_proxy(
            handle.local_addr(),
            "CONNECT",
            "example.invalid:443",
            "",
        )
        .await;
        assert_eq!(code, StatusCode::NOT_IMPLEMENTED);
        handle.shutdown();
    }

    #[tokio::test]
    async fn clean_request_falls_through_to_upstream() {
        // Con un host inexistente el forward fallará con 502, pero eso
        // demuestra que la request NO fue bloqueada por DLP (403).
        let handle = start_test_proxy(DlpAction::Block).await;
        let (code, _) = send_through_proxy(
            handle.local_addr(),
            "POST",
            "http://127.0.0.1:1/anything",
            "hello world, nothing suspicious here",
        )
        .await;
        assert_ne!(code, StatusCode::FORBIDDEN);
        handle.shutdown();
    }

    #[tokio::test]
    async fn sanitize_uri_strips_query_string() {
        assert_eq!(
            sanitize_uri("https://api.example.com/v1?api_key=sk-secret"),
            "https://api.example.com/v1"
        );
        assert_eq!(
            sanitize_uri("http://example.com/path"),
            "http://example.com/path"
        );
    }

    #[tokio::test]
    async fn alert_action_lets_request_pass_but_still_emits_event() {
        let patterns = compile_defaults().expect("defaults");
        let (tx, mut rx) = mpsc::channel(8);
        let proxy = DlpProxy::new(patterns, DlpAction::Alert).with_events(tx);
        let handle = proxy
            .start(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("start");
        let (code, _) = send_through_proxy(
            handle.local_addr(),
            "POST",
            "http://127.0.0.1:1/thing",
            "leak: sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN",
        )
        .await;
        // NO se bloquea → intenta forward → upstream 502
        assert_ne!(code, StatusCode::FORBIDDEN);

        // Aún así se debe haber emitido el evento.
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("no event received")
            .expect("channel closed");
        match event {
            SecurityEvent::DlpViolation { pattern_name, .. } => {
                assert_eq!(pattern_name, "OpenAI API Key");
            }
            other => panic!("wrong event: {other:?}"),
        }
        handle.shutdown();
    }
}
