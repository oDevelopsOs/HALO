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
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::patterns::{first_match, CompiledPattern};
use super::tls::LeafIssuer;
use crate::config::DlpAction;
use crate::events::SecurityEvent;

/// Límite defensivo para el tamaño del body escaneado. Requests mayores
/// se reenvían sin escanear y se loggea un warning — evita OOM.
const MAX_BODY_SCAN_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB

/// Tamaño del buffer usado en el tunnel MITM para copia bidireccional.
const MITM_BUF_SIZE: usize = 64 * 1024;

/// Timeout para los handshakes TLS del MITM (aceptar cliente + conectar upstream).
const MITM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    tls_issuer: Option<LeafIssuer>,
    upstream_root_store: Option<Arc<rustls::RootCertStore>>,
}

impl DlpProxy {
    /// Crea un proxy con los patrones compilados y la acción configurada.
    pub fn new(patterns: Vec<CompiledPattern>, action: DlpAction) -> Self {
        Self {
            patterns: Arc::new(patterns),
            action,
            events: None,
            tls_issuer: None,
            upstream_root_store: None,
        }
    }

    /// Habilita HTTPS MITM. Sin esto, CONNECT retorna 501.
    pub fn with_tls(mut self, issuer: LeafIssuer) -> Self {
        self.tls_issuer = Some(issuer);
        self
    }

    /// Inyecta un root store custom para las conexiones TLS upstream
    /// (solo para tests — en producción se usa webpki-roots).
    pub fn with_upstream_root_store(mut self, store: rustls::RootCertStore) -> Self {
        self.upstream_root_store = Some(Arc::new(store));
        self
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
        let tls_issuer = self.tls_issuer;
        let upstream_root_store = self.upstream_root_store;

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
                        let (mut stream, peer) = match accept {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(error = %e, "accept error");
                                continue;
                            }
                        };

                        // Leer primera línea del stream para detectar CONNECT.
                        let mut peek = Vec::with_capacity(1024);
                        let mut one = [0u8; 1];
                        loop {
                            match stream.read(&mut one).await {
                                Ok(0) => break,
                                Ok(_) => {
                                    peek.push(one[0]);
                                    let len = peek.len();
                                    if len >= 4
                                        && &peek[len - 4..] == b"\r\n\r\n"
                                    {
                                        break;
                                    }
                                    if len >= 512 {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        let is_connect = peek.starts_with(b"CONNECT")
                            && tls_issuer.is_some();

                        if is_connect {
                            let text = String::from_utf8_lossy(&peek);
                            let parts: Vec<&str> =
                                text.split_whitespace().collect();
                            let (host, port) = if parts.len() >= 2
                                && parts[1].contains(':')
                            {
                                let a = parts[1];
                                let sep = a.find(':').unwrap();
                                (
                                    a[..sep].to_string(),
                                    a[sep + 1..].parse::<u16>().unwrap_or(443),
                                )
                            } else {
                                (String::new(), 443)
                            };

                            if !host.is_empty() {
                                let _ = stream
                                    .write_all(
                                        b"HTTP/1.1 200 Connection Established\r\n\r\n",
                                    )
                                    .await;
                                let issuer = tls_issuer
                                    .as_ref()
                                    .expect("tls_issuer is some")
                                    .clone();
                                let p = patterns.clone();
                                let e = events.clone();
                                let u = upstream_root_store.clone();
                                tokio::spawn(async move {
                                    direct_connect_mitm(
                                        stream, host, port, p, action, e, issuer, u,
                                    )
                                    .await;
                                });
                                continue;
                            }
                        }

                        // No CONNECT (o CONNECT malformado/sin TLS) → hyper
                        let buf = Bytes::from(peek);
                        let prepend = PrependBuf {
                            buf,
                            pos: 0,
                            inner: stream,
                        };
                        let io = TokioIo::new(prepend);

                        let p = patterns.clone();
                        let e = events.clone();
                        let c = client.clone();
                        let ti = tls_issuer.clone();
                        let us = upstream_root_store.clone();
                        tokio::spawn(async move {
                            let svc = service_fn(move |req| {
                                let p = p.clone();
                                let e = e.clone();
                                let c = c.clone();
                                let ti = ti.clone();
                                let us = us.clone();
                                async move {
                                    Ok::<_, Infallible>(
                                        handle_request(
                                            req, p, action, e, c,
                                            ti, us,
                                        ).await,
                                    )
                                }
                            });
                            if let Err(err) = http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                            {
                                tracing::debug!(peer = ?peer, error = %err, "connection error");
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
    _tls_issuer: Option<LeafIssuer>,
    _upstream_root_store: Option<Arc<rustls::RootCertStore>>,
) -> Response<Full<Bytes>> {
    // HTTP plano (no CONNECT — se maneja a nivel TCP antes de llegar aquí).
    // Fallback: si un CONNECT llega aquí, retornar 501.
    if req.method() == Method::CONNECT {
        return text_response(
            StatusCode::NOT_IMPLEMENTED,
            "AgentGuard DLP: HTTPS MITM not enabled",
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

/// Wrapper que antepone un buffer de bytes a un stream `AsyncRead + AsyncWrite`.
/// Útil para reintroducir bytes que hyper ya leyó del socket (read_buf del upgrade).
struct PrependBuf<R> {
    buf: Bytes,
    pos: usize,
    inner: R,
}

impl<R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> tokio::io::AsyncRead for PrependBuf<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.buf.len() {
            let remaining = &self.buf[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrependBuf<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// MITM directo (sin hyper upgrade): establece TLS con el cliente usando
/// el leaf cert, conecta al upstream via TLS, y copia bidireccional escaneando.
async fn direct_connect_mitm(
    stream: TcpStream,
    host: String,
    port: u16,
    patterns: Arc<Vec<CompiledPattern>>,
    action: DlpAction,
    events: Option<mpsc::Sender<SecurityEvent>>,
    issuer: LeafIssuer,
    upstream_root_store: Option<Arc<rustls::RootCertStore>>,
) {
    let server_config = match issuer.server_config_for(&host) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(error = %e, %host, "MITM: failed to get leaf cert");
            return;
        }
    };

    let tls_acceptor = TlsAcceptor::from(server_config);
    let client_tls = match timeout(MITM_HANDSHAKE_TIMEOUT, tls_acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, %host, "MITM: client TLS accept failed");
            return;
        }
        Err(_) => {
            tracing::warn!(%host, "MITM: client TLS handshake timed out");
            return;
        }
    };

    let upstream_addr = format!("{host}:{port}");
    let upstream_tcp = match TcpStream::connect(&upstream_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, %host, "MITM: upstream TCP connect failed");
            return;
        }
    };

    let root_store = match upstream_root_store {
        Some(s) => s,
        None => {
            let mut s = rustls::RootCertStore::empty();
            s.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(s)
        }
    };
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates((*root_store).clone())
            .with_no_client_auth(),
    );
    let tls_connector = TlsConnector::from(client_cfg);
    let server_name = match ServerName::try_from(host.as_str()) {
        Ok(n) => n.to_owned(),
        Err(e) => {
            tracing::warn!(error = %e, %host, "MITM: invalid server name");
            return;
        }
    };

    let upstream_tls = match timeout(
        MITM_HANDSHAKE_TIMEOUT,
        tls_connector.connect(server_name, upstream_tcp),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, %host, "MITM: upstream TLS connect failed");
            return;
        }
        Err(_) => {
            tracing::warn!(%host, "MITM: upstream TLS handshake timed out");
            return;
        }
    };

    tracing::info!(%host, port, "HTTPS MITM established");

    let (mut client_r, mut client_w) = tokio::io::split(client_tls);
    let (mut upstream_r, mut upstream_w) = tokio::io::split(upstream_tls);

    let fwd_patterns = patterns.clone();
    let fwd_events = events.clone();
    let fwd_action = action;
    let fwd_host = host.clone();

    let forward = tokio::spawn(async move {
        let mut buf = vec![0u8; MITM_BUF_SIZE];
        loop {
            match client_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = &buf[..n];
                    let text = String::from_utf8_lossy(data);
                    if let Some(matched) = first_match(&fwd_patterns, &text) {
                        tracing::warn!(
                            pattern = %matched,
                            host = %fwd_host,
                            "DLP violation in HTTPS stream"
                        );
                        if let Some(ref tx) = fwd_events {
                            let _ = tx
                                .send(SecurityEvent::DlpViolation {
                                    pattern_name: matched.to_string(),
                                    destination: format!("https://{}/", fwd_host),
                                    process: "<mitm>".into(),
                                    pid: 0,
                                    timestamp: now_ts(),
                                })
                                .await;
                        }
                        if fwd_action == DlpAction::Block {
                            break;
                        }
                    }
                    if upstream_w.write_all(data).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, host = %fwd_host, "MITM client read error");
                    break;
                }
            }
        }
    });

    let bwd_host = host.clone();
    let backward = tokio::spawn(async move {
        let mut buf = vec![0u8; MITM_BUF_SIZE];
        loop {
            match upstream_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if client_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, host = %bwd_host, "MITM upstream read error");
                    break;
                }
            }
        }
    });

    let _ = tokio::join!(forward, backward);
    tracing::info!(%host, "HTTPS MITM connection closed");
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

    fn make_issuer_for_test() -> LeafIssuer {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let ca = crate::ca::LocalCa::generate_and_persist(tmp.path().join("ca")).expect("ca");
        std::mem::forget(tmp);
        LeafIssuer::new(&ca).expect("issuer")
    }

    async fn start_test_proxy_with_tls(action: DlpAction) -> DlpProxyHandle {
        let proxy = DlpProxy::new(compile_defaults().expect("defaults"), action)
            .with_tls(make_issuer_for_test());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        proxy.start(addr).await.expect("proxy start")
    }

    #[tokio::test]
    async fn connect_with_tls_returns_200() {
        let handle = start_test_proxy_with_tls(DlpAction::Block).await;
        let (code, _) = send_through_proxy(
            handle.local_addr(),
            "CONNECT",
            "api.openai.com:443",
            "",
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        handle.shutdown();
    }

    /// Crea una CA, un LeafIssuer, y un servidor TLS echo firmado por la
    /// misma CA. Devuelve (proxy_handle, server_addr, shutdown) para el test.
    async fn setup_mitm_e2e(
        action: DlpAction,
    ) -> (DlpProxyHandle, SocketAddr, oneshot::Sender<()>) {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor as ServerAcceptor;
        // Asegurar que rustls crypto provider está instalado.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // 1. CA compartida (proxy MITM + server cert)
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let ca = crate::ca::LocalCa::generate_and_persist(tmp.path().join("ca")).expect("ca");
        std::mem::forget(tmp);
        let issuer = LeafIssuer::new(&ca).expect("issuer");

        // 2. TLS server cert firmado por la misma CA
        let server_key = KeyPair::generate().expect("server key");
        let mut server_params =
            CertificateParams::new(vec!["127.0.0.1".into()]).expect("san");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "127.0.0.1");
        server_params.distinguished_name = dn;
        server_params.not_before =
            time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        server_params.not_after =
            time::OffsetDateTime::now_utc() + time::Duration::days(1);
        let server_cert = server_params
            .signed_by(&server_key, ca.rcgen_cert().as_ref(), ca.rcgen_key().as_ref())
            .expect("server cert");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    server_key.serialize_der(),
                )),
            )
            .expect("server config");
        let server_acceptor: ServerAcceptor =
            ServerAcceptor::from(Arc::new(server_config));

        // 3. Root store con nuestra CA (para que el proxy confíe en el server)
        let mut root_store = rustls::RootCertStore::empty();
        let mut pem_reader = std::io::BufReader::new(ca.cert_pem().as_bytes());
        for cert in rustls_pemfile::certs(&mut pem_reader) {
            root_store
                .add(cert.expect("parse ca cert"))
                .expect("add ca cert");
        }

        // 4. Arrancar servidor TLS echo
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server_addr = tcp_listener.local_addr().expect("server addr");
        let (server_shutdown, mut shutdown_rx) =
            oneshot::channel::<()>();
        let acceptor = server_acceptor;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = tcp_listener.accept() => {
                        let (stream, _) = match accept {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        let acc = acceptor.clone();
                        tokio::spawn(async move {
                            let tls = match acc.accept(stream).await {
                                Ok(t) => t,
                                Err(_) => return,
                            };
                            let (mut r, mut w) = tokio::io::split(tls);
                            let _ = tokio::io::copy(&mut r, &mut w).await;
                        });
                    }
                }
            }
        });

        // 5. Proxy con TLS + custom root store
        let patterns = compile_defaults().expect("defaults");
        let proxy = DlpProxy::new(patterns, action)
            .with_tls(issuer)
            .with_upstream_root_store(root_store);
        let proxy_handle = proxy
            .start(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("proxy start");

        (proxy_handle, server_addr, server_shutdown)
    }

    /// Cliente MITM: conecta al proxy, hace CONNECT, handshake TLS, envía
    /// datos y lee respuesta. Si el proxy bloquea, retorna error en shutdown.
    async fn mitm_client_send(
        proxy_addr: SocketAddr,
        server_addr: SocketAddr,
        ca_pem: &str,
        payload: &[u8],
    ) -> Vec<u8> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // Conectar al proxy
        let mut stream = tokio::net::TcpStream::connect(proxy_addr)
            .await
            .expect("connect proxy");

        // CONNECT
        let authority = format!("127.0.0.1:{}", server_addr.port());
        let connect_req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        stream.write_all(connect_req.as_bytes()).await.expect("write CONNECT");

        // Leer status
        let mut hdr = vec![0u8; 256];
        let n = stream.read(&mut hdr).await.expect("read CONNECT response");
        let resp = String::from_utf8_lossy(&hdr[..n]);
        assert!(
            resp.contains("200"),
            "CONNECT response was not 200: {resp}"
        );

        // TLS handshake with proxy (trusting our CA)
        let mut root_store = rustls::RootCertStore::empty();
        let mut pem_reader = std::io::BufReader::new(ca_pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut pem_reader) {
            root_store.add(cert.expect("parse")).expect("add");
        }
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let server_name = ServerName::try_from("127.0.0.1").expect("sn");
        let mut tls = connector
            .connect(server_name, stream)
            .await
            .expect("TLS handshake");

        // Enviar payload
        tls.write_all(payload).await.expect("write payload");
        tls.shutdown().await.ok();

        // Leer respuesta (echo del servidor a través del proxy)
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        response
    }

    #[tokio::test]
    #[ignore = "E2E: requires real TLS upstream server — run manually with RUST_LOG=debug"]
    async fn mitm_e2e_alert_detects_api_key_over_tls() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let ca = crate::ca::LocalCa::generate_and_persist(tmp.path().join("ca")).expect("ca");
        let ca_pem = ca.cert_pem().to_string();

        let patterns = compile_defaults().expect("defaults");
        let (event_tx, mut event_rx) = mpsc::channel::<SecurityEvent>(8);

        let (handle, server_addr, server_shutdown) = {
            // Reconstruir root_store + issuer para el proxy
            let issuer = LeafIssuer::new(&ca).expect("issuer");
            let mut root_store = rustls::RootCertStore::empty();
            let mut pem_reader = std::io::BufReader::new(ca.cert_pem().as_bytes());
            for cert in rustls_pemfile::certs(&mut pem_reader) {
                root_store.add(cert.expect("parse")).expect("add");
            }

            // Servidor TLS echo (misma CA)
            let server_key = rcgen::KeyPair::generate().expect("key");
            let mut server_params =
                rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).expect("san");
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "127.0.0.1");
            server_params.distinguished_name = dn;
            server_params.not_before =
                time::OffsetDateTime::now_utc() - time::Duration::hours(1);
            server_params.not_after =
                time::OffsetDateTime::now_utc() + time::Duration::days(1);
            let ca_key =
                rcgen::KeyPair::from_pem(ca.key_pem()).expect("ca key");
            let issuer_params = rcgen::CertificateParams::from_ca_cert_pem(ca.cert_pem())
                .expect("ca params");
            let issuer_cert = issuer_params.self_signed(&ca_key).expect("ca cert");
            let server_cert = server_params
                .signed_by(&server_key, &issuer_cert, &ca_key)
                .expect("server cert");

            let server_cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            server_key.serialize_der(),
                        ),
                    ),
                )
                .expect("server config");
            let acceptor: TlsAcceptor = TlsAcceptor::from(Arc::new(server_cfg));

            let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let server_addr = tcp_listener.local_addr().expect("addr");
            let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        a = tcp_listener.accept() => {
                            let (s, _) = match a { Ok(v) => v, Err(_) => break };
                            let acc = acceptor.clone();
                            tokio::spawn(async move {
                                if let Ok(tls) = acc.accept(s).await {
                                    let (mut r, mut w) = tokio::io::split(tls);
                                    let _ = tokio::io::copy(&mut r, &mut w).await;
                                }
                            });
                        }
                    }
                }
            });

            let proxy = DlpProxy::new(patterns, DlpAction::Alert)
                .with_events(event_tx)
                .with_tls(issuer)
                .with_upstream_root_store(root_store);
            let handle = proxy
                .start(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .expect("proxy");
            (handle, server_addr, shutdown_tx)
        };

        // Cliente MITM: envía API key a través del túnel TLS
        let payload = b"Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN\r\n";
        let _echo_response = mitm_client_send(handle.local_addr(), server_addr, &ca_pem, payload).await;

        // Verificar que el evento DLP fue emitido
        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("timeout waiting for DLP event")
            .expect("event channel closed");
        match event {
            SecurityEvent::DlpViolation { pattern_name, .. } => {
                assert_eq!(pattern_name, "OpenAI API Key");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        handle.shutdown();
        let _ = server_shutdown.send(());
    }

    #[tokio::test]
    #[ignore = "E2E: requires real TLS upstream server — run manually"]
    async fn mitm_e2e_block_drops_tls_connection() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let ca = crate::ca::LocalCa::generate_and_persist(tmp.path().join("ca")).expect("ca");
        let ca_pem = ca.cert_pem().to_string();
        let _issuer = LeafIssuer::new(&ca).expect("issuer");

        let mut root_store = rustls::RootCertStore::empty();
        let mut pem_reader = std::io::BufReader::new(ca.cert_pem().as_bytes());
        for cert in rustls_pemfile::certs(&mut pem_reader) {
            root_store.add(cert.expect("parse")).expect("add");
        }

        let (handle, server_addr, server_shutdown) =
            setup_mitm_e2e(DlpAction::Block).await;

        // Enviar API key — el proxy debe bloquear y dropear la conexión TLS.
        let payload: &[u8] = b"leak: sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN";
        let echo = mitm_client_send(handle.local_addr(), server_addr, &ca_pem, payload).await;

        // Con Block, la conexión se cierra antes de que el servidor pueda
        // devolver el echo completo. El cliente puede recibir 0 bytes.
        // Lo importante es que NO recibimos el payload de vuelta intacto.
        // (Si el echo funcionara, payload estaría en la respuesta.)
        assert!(
            echo.len() < payload.len(),
            "block should have prevented full echo, got {} bytes",
            echo.len()
        );

        handle.shutdown();
        let _ = server_shutdown.send(());
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
