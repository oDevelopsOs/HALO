---
trigger: always_on
description: Rules for logging secrets, incidents, and sensitive data
---

# Security Logging

- **Nunca** loggear el **valor** de un secreto detectado por el DLP. Solo:
  - Nombre del patrón (`"OpenAI API Key"`).
  - Destino (URI sin query string con credenciales).
  - Nombre del proceso y PID.
  - Timestamp.
- **Formato:** `tracing` + `tracing-subscriber` con layer JSON en producción, layer `fmt` en dev.
- **Niveles:**
  - `error!`: fallos que impiden operación (no se pudo cargar eBPF, IPC caído).
  - `warn!`: violaciones detectadas y acciones bloqueadas.
  - `info!`: arranque, shutdown, cambios de configuración.
  - `debug!`/`trace!`: solo en dev, nunca activos en release por defecto.
- **Incidentes persistidos:** append-only a `incidents.jsonl` (una línea JSON por incidente). Rotación externa (logrotate/systemd journal).
- **Nunca** loggear:
  - Contenidos de archivos protegidos.
  - Headers `Authorization`, `Cookie`, `X-Api-Key` completos (truncar a primeros 4 chars + `...`).
  - Bodies de requests HTTP del DLP proxy.
- **PII:** rutas con nombre de usuario (`/home/alice/...`) son aceptables en logs locales, pero al enviar telemetría (si existiera) ofuscar con `~/...`.
- **Auditabilidad:** cada decisión de bloqueo debe dejar un incidente trazable con campos estables (schema versionado).
