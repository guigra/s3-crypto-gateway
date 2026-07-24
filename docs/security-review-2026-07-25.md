# Revisión de seguridad y registro de decisiones

- **Fecha:** 2026-07-25
- **Estado:** Fase 1 implementada en `security/remediation-phase1`, pendiente de
  revisión, CI y merge
- **Alcance:** gateway HTTP/S3, configuración, gestión de claves, formato CLPE,
  cliente S3 y cadena de suministro
- **Componentes revisados:** `main.go`, `config.go`, `keys.go`, `s3.go`,
  `pkg/clpe`, `Containerfile`, pipelines de GitHub Actions y Jenkins

## Objetivo del documento

Este documento conserva la trazabilidad de la revisión de seguridad, las
decisiones acordadas con el equipo de seguridad y la separación entre:

1. correcciones compatibles que se implementarán a corto plazo;
2. mejoras de documentación y despliegue;
3. cambios de arquitectura que requieren diseño y coordinación entre
   repositorios.

No representa por sí mismo una remediación. Mientras los cambios indicados no
se hayan integrado, el comportamiento vulnerable o incompleto descrito aquí
sigue presente.

## Resumen ejecutivo

Los siete hallazgos de la revisión han sido verificados contra el código y
aceptados. No se identificaron falsos positivos.

El cifrado AES-256-GCM y el uso de una DEK aleatoria por objeto son una base
correcta, pero el servicio depende de una frontera de confianza de red que no
se entrega actualmente en este repositorio. También existen riesgos de
denegación de servicio, un `panic` con sobres truncados, configuración SSE-C
fail-open y diferencias importantes respecto a una implementación completa de
la API S3.

La remediación se dividirá para no romper:

- la compatibilidad binaria de CLPE1 con `logback-clp-s3-appender`;
- la semántica deliberada `ETag = MD5(plaintext)`;
- la reproducibilidad, firma Cosign, SBOM y procedencia SLSA de las releases.

## Hallazgos y decisiones

### SEC-01 — Ausencia de autenticación y autorización de clientes

- **Severidad:** crítica si el puerto queda expuesto fuera de la frontera de
  confianza; decisión de diseño conocida en un clúster correctamente aislado.
- **Estado:** aceptado; mitigación de despliegue a corto plazo y proyecto de
  autenticación diferido.
- **Evidencia:** `main.go` enruta las peticiones sin validar SigV4 ni otra
  identidad. El cliente de backend vuelve a firmarlas con una única identidad
  AWS.
- **Impacto:** cualquier cliente que alcance el gateway hereda indirectamente
  todos los permisos S3 de las credenciales del servicio, incluidos lectura,
  escritura, listado o borrado.

**Decisión a corto plazo**

- Documentar de forma visible que el endpoint no debe exponerse a redes no
  confiables.
- Entregar una `NetworkPolicy` restrictiva en el repositorio standalone, con
  una política segura por defecto y parámetros explícitos para los clientes
  autorizados.
- Documentar mTLS, un bearer-auth proxy u otro frontal autenticador como
  opciones de despliegue.
- Recomendar credenciales S3 de mínimo privilegio.

**Diferido**

- La validación SigV4 completa o un mecanismo nativo equivalente se tratará
  como una feature de arquitectura, no como un parche rápido.

### SEC-02 — Consumo de memoria sin límites y servidor sin timeouts

- **Severidad:** alta.
- **Estado:** aceptado; corrección inmediata planificada.
- **Evidencia:** PUT y GET utilizan `io.ReadAll`; el servidor usa
  `http.ListenAndServe` sin límites ni timeouts explícitos.
- **Impacto:** objetos grandes, concurrencia o clientes lentos pueden agotar
  memoria, conexiones o descriptores y provocar una denegación de servicio.

**Decisión a corto plazo**

- Sustituir `ListenAndServe` por un `http.Server` con `ReadHeaderTimeout`,
  `ReadTimeout`, `WriteTimeout` e `IdleTimeout` configurables y valores
  conservadores por defecto.
- Limitar PUT mediante `http.MaxBytesReader`, con tamaño máximo configurable y
  una respuesta S3 estable cuando se supere.
- Limitar también la lectura desde el backend en GET y fallar de forma
  controlada antes de agotar memoria.
- Añadir pruebas para límites, timeouts configurables y respuestas de error.

**Diferido**

- El soporte eficiente de objetos grandes requiere un formato de cifrado por
  chunks autenticados o almacenamiento temporal controlado. Se diseñará junto
  con la evolución del formato, sin alterar CLPE1.

### SEC-03 — Tenant y ubicación del objeto no autenticados por el sobre

- **Severidad:** alta como debilidad de aislamiento y defensa en profundidad.
- **Estado:** quick win planificado; AAD diferido a CLPE2.
- **Evidencia:** `Decrypt` selecciona la KEK usando el tenant embebido en el
  sobre. GET no comprueba que coincida con el tenant derivado del key. AES-GCM
  usa AAD `nil`, por lo que bucket, key y tenant no quedan ligados
  criptográficamente al ciphertext.
- **Impacto:** un sobre puede moverse o reproducirse bajo otra ubicación y
  seguir descifrándose. Esto sería especialmente relevante al introducir
  autorización por prefijos o tenants.

**Decisión a corto plazo**

- Exponer de forma segura el tenant del encabezado CLPE y comprobar en GET que
  coincide con `tenantOf(key)` antes de descifrar.
- Rechazar inconsistencias sin revelar detalles internos.
- Añadir pruebas de traslado de objetos entre tenants.

**Diferido**

- Diseñar CLPE2 con AAD que autentique al menos tenant y contexto de ubicación.
- Coordinar formato, vectores de prueba, migración y lectura retrocompatible
  con `logback-clp-s3-appender`.
- CLPE1 no cambiará de forma incompatible.

### SEC-04 — `panic` al descifrar un sobre CLPE truncado

- **Severidad:** media.
- **Estado:** corrección inmediata planificada.
- **Evidencia:** `IsEnvelope` acepta los cuatro bytes `CLPE`, pero `Decrypt`
  accede después a `env[4]` sin comprobar antes la longitud mínima.
- **Impacto:** una entrada truncada provoca `index out of range`. El servidor
  HTTP normalmente recupera el `panic` de la petición, pero permite cierres de
  conexión, consumo de recursos y ruido de logs.

**Decisión a corto plazo**

- Validar la longitud mínima antes de leer versión y `tenantLen`.
- Revisar todas las operaciones de índices y longitudes del parser.
- Añadir casos de regresión para entradas de 0 a la longitud mínima.
- Añadir fuzzing de `Decrypt` con la propiedad de que ninguna entrada arbitraria
  puede provocar `panic`.

### SEC-05 — Configuración criptográfica fail-open

- **Severidad:** media.
- **Estado:** corrección inmediata planificada; modo estricto posterior.
- **Evidencia:** con `SSEC_ENABLED=true`, una `SSEC_KEY` ausente, inválida o de
  longitud incorrecta termina produciendo `nil` y desactiva SSE-C sin impedir
  el arranque.
- **Impacto:** el operador puede creer que existe una capa criptográfica que en
  realidad no se está aplicando. Los filtros de cifrado también pueden dejar
  objetos en claro por una configuración errónea.

**Decisión a corto plazo**

- Hacer que la carga de configuración devuelva error.
- Fallar al arrancar cuando SSE-C esté habilitado y su clave no sea exactamente
  una clave base64 válida de 32 bytes.
- Validar valores booleanos y numéricos en vez de aceptar silenciosamente
  valores desconocidos.
- Añadir pruebas de arranque para configuraciones inválidas.

**Diferido**

- Añadir un modo estricto de política que rechace keys sin tenant válido o fuera
  del ámbito de cifrado, en vez de almacenarlas en claro.

### SEC-06 — Subconjunto S3 incompleto presentado como proxy transparente

- **Severidad:** media.
- **Estado:** documentación y rechazo explícito planificados; ampliación de API
  incremental.
- **Evidencia:** solo se implementan PUT simple, GET completo, HEAD, DELETE y
  ListObjectsV2. No se implementan, entre otros, Range/206, multipart,
  condicionales, CopyObject, versionado ni checksums completos.
- **Impacto:** clientes que esperan semántica S3 completa pueden descargar más
  datos de los solicitados, fallar, reintentar o detectar cambios permanentes.
  HEAD y LIST reflejan actualmente tamaño y ETag del ciphertext mientras GET
  refleja el plaintext.

**Decisión a corto plazo**

- Reemplazar las afirmaciones “transparent proxy”, “any S3 client works” y
  “no application changes” por una descripción precisa del subconjunto
  soportado y sus limitaciones.
- Detectar parámetros, cabeceras y operaciones conocidas pero no soportadas y
  devolver un error explícito (`501 NotImplemented` con XML S3), en lugar de
  ignorarlos o ejecutar otra operación.
- Crear pruebas de contrato para las operaciones soportadas y rechazadas.

**Compatibilidad que se conserva**

- No se cambiará de forma aislada `ETag = MD5(plaintext)`. Es una semántica
  deliberada y cualquier evolución se estudiará con los clientes afectados.

**Diferido**

- Priorizar Range y multipart según las necesidades reales de los clientes.
- Diseñar la semántica coherente de HEAD/LIST para objetos cifrados antes de
  modificar las respuestas actuales.

### SEC-07 — Errores internos expuestos a clientes

- **Severidad:** baja.
- **Estado:** corrección inmediata planificada.
- **Evidencia:** varias respuestas incluyen directamente `err.Error()` del SDK,
  configuración o cifrado.
- **Impacto:** pueden revelarse endpoint, nombres, identificadores de petición y
  otros detalles operativos.

**Decisión a corto plazo**

- Generar un identificador de error o petición.
- Registrar internamente el error completo con ese identificador.
- Devolver al cliente un código y mensaje S3 estable y genérico.
- No registrar claves, cabeceras SSE-C, credenciales ni cuerpos.

## Plan de ejecución acordado

### Fase 1 — Quick wins compatibles

Un primer PR, sin cambios de formato, incluirá:

1. protección completa del parser CLPE frente a entradas truncadas y fuzzing;
2. timeouts del servidor;
3. límites configurables de PUT y GET;
4. validación SSE-C fail-closed al arrancar;
5. comprobación `tenant del sobre == tenant derivado del key`;
6. sanitización de errores y correlación con logs.

### Fase 2 — Contrato y despliegue seguro

Uno o más PR posteriores incluirán:

1. documentación precisa del subconjunto S3;
2. respuestas explícitas para funciones no soportadas;
3. pruebas de contrato S3;
4. `NetworkPolicy` restrictiva y documentación de la frontera de confianza.

### Fase 3 — Proyectos de arquitectura

Se gestionarán por separado:

1. autenticación nativa SigV4 o frontal autenticador soportado;
2. CLPE2 con AAD y, si se aprueba, cifrado por chunks;
3. coordinación de CLPE2 con el appender Java y estrategia de migración;
4. ampliación priorizada de la API S3.

## Condiciones de aceptación

Toda remediación deberá:

- entrar mediante rama y pull request;
- pasar `go vet`, tests, detector de carreras y `govulncheck`;
- pasar CodeQL y Gitleaks en CI;
- incluir pruebas de regresión para el riesgo corregido;
- no modificar CLPE1 de forma incompatible;
- no cambiar sin diseño previo el ETag del plaintext;
- conservar el build reproducible y la cadena de firma, SBOM y procedencia;
- actualizar este documento cuando una decisión cambie o una fase se complete.

## Validaciones realizadas durante la revisión

La revisión inicial verificó:

- build completo del `Containerfile`;
- `go vet ./...`;
- `go test ./...`;
- `go test -race ./...`;
- `govulncheck ./...`, sin vulnerabilidades conocidas en las rutas analizadas;
- búsqueda local de patrones de secretos, sin credenciales reales detectadas;
- configuración de CodeQL, Gitleaks y Dependabot en GitHub Actions;
- bases y acciones fijadas por digest o commit, ejecución como usuario no root,
  Cosign, SBOM y procedencia SLSA.

Estas validaciones no sustituyen pruebas de integración contra cada backend S3
compatible ni una prueba de penetración del despliegue real.

## Historial de estado

| Fecha | Cambio |
|---|---|
| 2026-07-25 | Auditoría inicial completada; siete hallazgos identificados. |
| 2026-07-25 | Equipo de seguridad verifica los siete hallazgos y aprueba el plan con separación explícita de SigV4 y CLPE2. |
| 2026-07-25 | Se documentan decisiones y fases; todavía no se han integrado remediaciones de código. |
| 2026-07-25 | Se inicia la Fase 1 en `security/remediation-phase1`: parser seguro, límites/timeouts, SSE-C fail-closed, vínculo tenant-ruta y errores sanitizados. |
| 2026-07-25 | Implementación de Fase 1 completada en la rama; build, vet, tests, race, fuzzing y `govulncheck` superados. Pendiente de revisión y CI remoto. |
