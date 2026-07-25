# ADR-0001: Autenticación y autorización de entrada

- **Estado:** Propuesto
- **Fecha:** 2026-07-25
- **Decisores:** producto, seguridad, plataforma y responsables de clientes S3
- **Ámbito:** data plane HTTP/S3 de `s3-crypto-gateway`

## Contexto

El gateway acepta actualmente cualquier petición que alcance su puerto y la
vuelve a firmar hacia el backend con una identidad AWS propia. La
`NetworkPolicy` reduce la superficie de red, pero no establece la identidad del
llamante ni limita sus operaciones por bucket, prefijo o tenant.

El servicio debe seguir siendo consumible por herramientas S3 existentes. Debe
además funcionar detrás de ingress o balanceadores, permitir rotación de
identidades y mantener separadas las credenciales de clientes y las del
backend.

SigV4, mTLS y bearer resuelven problemas diferentes:

- SigV4 autentica e integra criptográficamente el mensaje S3;
- mTLS autentica el peer y protege el canal entre dos terminaciones TLS;
- bearer representa una autorización portable, pero quien roba el token puede
  usarlo mientras siga siendo válido, salvo que se ligue a una clave.

## Decisión propuesta

Adoptar una defensa por capas:

1. **SigV4 obligatorio en el data plane S3** para autenticar la petición.
2. **Autorización deny-by-default** asociada al principal SigV4.
3. **TLS obligatorio y mTLS recomendado** para identidad adicional del
   workload dentro del perímetro.
4. **NetworkPolicy obligatoria** como reducción de superficie, no como
   autenticación.
5. Reservar **OAuth2 bearer** para un futuro plano administrativo o un frontal
   de API; no introducirlo inicialmente en el protocolo S3.

Las credenciales SigV4 de entrada y las credenciales AWS de salida serán
identidades diferentes, almacenadas y rotadas por separado.

Este ADR no aprueba todavía una implementación. Su estado debe cambiar a
`Aceptado` después de validar compatibilidad y operación con los clientes
reales.

## Arquitectura

```text
Cliente S3
   │
   ├── TLS/mTLS ─────────── identidad de workload y canal
   └── SigV4 ────────────── identidad e integridad del mensaje
              │
              ▼
       s3-crypto-gateway
       ├── verifica SigV4
       ├── resuelve principal
       ├── autoriza operación/bucket/prefix/tenant
       ├── cifra o descifra
       └── firma hacia S3 con otra identidad
```

## Verificación SigV4

### Alcance inicial

La primera implementación soportará:

- `AWS4-HMAC-SHA256` mediante cabecera `Authorization`;
- payload SHA-256 explícito;
- las operaciones S3 que el contrato del gateway ya soporta;
- reloj con una desviación máxima configurable, inicialmente cinco minutos;
- comparación de firmas en tiempo constante;
- región y servicio (`s3`) validados contra la configuración;
- credenciales temporales únicamente si el token de sesión puede validarse
  contra el proveedor de identidades configurado.

Se diferirán hasta disponer de pruebas específicas:

- streaming chunked SigV4;
- SigV4a;
- payload mediante trailers;
- URLs prefirmadas;
- `UNSIGNED-PAYLOAD`, salvo que se apruebe para un perfil concreto y siempre
  bajo TLS.

Una función no soportada fallará explícitamente; nunca degradará a una petición
sin autenticar.

### Canonicalización

La implementación no reconstruirá la URL a partir de una versión ya
normalizada si eso cambia su representación firmada. Debe probar:

- path escapado y segmentos que contienen caracteres reservados;
- query parameters repetidos, vacíos y ordenados;
- espacios y valores duplicados en headers firmados;
- nombres de header sin distinción de mayúsculas;
- `host`, puertos no estándar y terminación TLS en proxy;
- claves con UTF-8 y caracteres escapados;
- payload vacío, binario y cercano al límite configurado.

Se usarán vectores oficiales y peticiones generadas por AWS CLI y los SDK
admitidos. La canonicalización no se considerará correcta basándose únicamente
en tests escritos por la propia implementación.

### Anti-replay

SigV4 limita temporalmente una firma, pero una petición capturada puede
repetirse dentro de la ventana válida. TLS impide reproducir registros dentro
de una sesión, no el reenvío de una petición mediante una sesión nueva.

La primera versión:

- exigirá timestamp y ventana corta;
- rechazará timestamps futuros fuera de tolerancia;
- documentará que PUT y DELETE soportados son idempotentes respecto a la misma
  ruta;
- no añadirá inicialmente un replay cache que pueda romper reintentos legítimos
  de SDKs.

Antes de admitir operaciones no idempotentes, se decidirá entre nonce,
idempotency key o replay cache acotado.

## Gestión de identidades

El verificador SigV4 necesita recuperar el secreto compartido del access key;
un hash irreversible no es suficiente. Los secretos:

- se almacenarán cifrados en Vault, KMS o un secret store equivalente;
- no compartirán material con las credenciales del backend;
- tendrán identificador, estado, creación, expiración y propietario;
- permitirán solapamiento de dos claves durante rotación;
- nunca aparecerán en logs, métricas, errores o trazas;
- se cargarán mediante una interfaz de proveedor, no mediante lógica acoplada a
  variables de entorno.

Una clave desconocida, deshabilitada, expirada o cuya fuente no esté disponible
fallará cerrada.

## Modelo de autorización

Cada principal tendrá una o más reglas con:

- operaciones permitidas: PUT, GET, HEAD, DELETE y LIST;
- buckets permitidos;
- prefijos permitidos;
- tenants permitidos;
- tamaño máximo opcional;
- requisitos adicionales de identidad mTLS, si aplica.

La evaluación será deny-by-default. No se permitirá una regla vacía que
signifique implícitamente “todo”.

### Objetos

Para PUT, GET, HEAD y DELETE:

1. autenticar la petición;
2. normalizar bucket y key una sola vez;
3. autorizar operación, bucket y prefijo;
4. derivar tenant de la key y autorizarlo;
5. ejecutar la operación;
6. en objetos cifrados, conservar las comprobaciones de tenant y AAD de CLPE2.

### ListObjectsV2

LIST requiere tratamiento específico. El `prefix` solicitado debe estar dentro
de un prefijo autorizado. Una identidad limitada a `logs/tenant-a/` no podrá:

- listar sin prefix;
- listar `logs/`;
- usar un delimiter para inferir otros tenants;
- reutilizar un continuation token fuera del ámbito autorizado.

Los tokens de continuación se pasarán al backend únicamente después de
autorizar bucket y prefix. Deben añadirse pruebas que verifiquen que paginar no
amplía el ámbito.

## mTLS

mTLS se usará como control adicional:

- preferentemente con SPIFFE/SPIRE, service mesh o cert-manager;
- certificados de corta duración y rotación automatizada;
- identidad tomada de URI SAN/SPIFFE ID o de un campo acordado, no de un
  `CommonName` ambiguo;
- política explícita que pueda exigir correspondencia entre identidad mTLS y
  principal SigV4.

### Terminación en ingress

Si mTLS termina antes del gateway, una cabecera con identidad de cliente deja de
ser una prueba criptográfica extremo a extremo. Solo se confiará en ella cuando:

- el gateway solo sea alcanzable desde proxies autorizados;
- el proxy elimine cualquier valor aportado por el cliente;
- proxy y gateway se autentiquen mutuamente;
- la cabecera usada tenga un nombre reservado y documentado;
- existan pruebas de inyección y rutas alternativas.

## Bearer y prueba de posesión

Bearer no se añadirá al data plane S3 inicial porque los clientes objetivo ya
implementan SigV4 y un token adicional reduciría interoperabilidad.

Puede adoptarse en:

- API administrativa;
- interfaz web;
- emisión y rotación de identidades;
- un frontal OAuth2 que traduzca una identidad autorizada.

Si se requiere bearer en un entorno hostil, se evaluará ligarlo mediante mTLS
(RFC 8705) o DPoP (RFC 9449). Tokens y cabeceras de autorización se excluirán de
logs, APM y capturas de soporte.

## Health y observabilidad

`/healthz` podrá permanecer sin autenticación únicamente si:

- no revela configuración ni estado sensible;
- la NetworkPolicy limita su exposición;
- se diferencia readiness de liveness cuando se añadan dependencias de
  identidad.

Se añadirán métricas sin access keys completas:

- éxito y fallo de autenticación por causa;
- denegaciones de autorización por operación;
- desfase de reloj observado;
- errores del proveedor de secretos;
- uso de formatos SigV4 diferidos o no soportados.

Los identificadores de principal usados en logs serán estables pero no secretos.

## Despliegue incremental

1. Implementar interfaces de proveedor de credenciales y políticas.
2. Añadir verificación SigV4 con vectores oficiales y tests cross-client.
3. Introducir modo de observación únicamente en entornos no productivos; nunca
   tratar una firma inválida como autenticada.
4. Inventariar las access keys usadas por clientes reales.
5. Activar autorización en staging con políticas deny-by-default.
6. Validar AWS CLI, SDKs y reintentos.
7. Activar enforcement en producción por grupos de clientes.
8. Añadir mTLS y vinculación de identidades donde la plataforma lo permita.
9. Evaluar URLs prefirmadas y formatos streaming según demanda.

Debe existir un procedimiento de rollback que restaure la versión anterior, no
un flag permanente que permita saltarse autenticación silenciosamente.

## Alternativas consideradas

### Solo NetworkPolicy

Rechazada como estado final: controla procedencia de red, no identidad de
aplicación, integridad del mensaje ni autorización por objeto.

### Solo mTLS

No seleccionada como única capa: no autentica el contenido S3, se debilita
cuando termina en un proxy y no proporciona por sí misma políticas por
bucket/prefijo.

### Solo bearer

No seleccionada para el data plane: peor encaje con clientes S3 y riesgo de uso
directo si se filtra. Sigue siendo adecuada para APIs HTTP convencionales.

### SigV4 sin mTLS

Válida técnicamente bajo TLS y puede ser el primer incremento, pero deja sin
identidad criptográfica de workload al canal. Se acepta como etapa de rollout,
no como objetivo final en entornos internos que ya dispongan de PKI
automatizada.

## Consecuencias

### Positivas

- compatibilidad conceptual con clientes S3;
- integridad de método, path, query, headers firmados y payload;
- autorización granular y auditable;
- separación de identidades de entrada y salida;
- defensa en profundidad cuando se combina con mTLS y NetworkPolicy.

### Costes y riesgos

- canonicalización SigV4 compleja;
- almacenamiento recuperable y rotación de secretos compartidos;
- operación de PKI para mTLS;
- riesgo de bloquear clientes por diferencias de reloj o formatos streaming;
- necesidad de políticas y pruebas específicas para LIST.

## Criterios para aceptar el ADR

- inventario de clientes y variantes SigV4 que emiten;
- decisión sobre proveedor de secretos y rotación;
- esquema de políticas revisado por seguridad;
- estrategia mTLS directa o mediante ingress;
- tratamiento acordado de URLs prefirmadas y streaming;
- pruebas de rendimiento y compatibilidad;
- plan de rollout y rollback aprobado.

## Evaluación de los mantenedores e input para la decisión (2026-07-25)

> Estado: **input, no decisión cerrada**. La decisión final es de los mantenedores.

**Valoración general — sólido.** Respaldamos los aciertos: SigV4 como elección
correcta para clientes S3 (interop), deny-by-default sin regla vacía = todo,
disciplina de canonicalización con **vectores oficiales** (el footgun nº1 de
SigV4), realismo anti-replay (no romper reintentos de SDK), secretos recuperables
separados del backend con rotación solapada, contención de ámbito en LIST
(prefix/delimiter/continuation-token) y rollout sin flag de bypass silencioso.

**Input 1 — proporcionalidad al despliegue real (mTLS-first por fases).** El ADR
está escrito para el caso general (endpoint S3 potencialmente expuesto / multi-tenant
/ terceros). El despliegue real de `clp-log-tier` es otro: el gateway es la frontera
S3 **interna** de unos pocos clientes de **primera parte** (gateway-go, phase2, search,
lifecycle) en el mismo dominio de confianza, tras NetworkPolicy + egress FortiProxy.
Para ese caso proponemos **fasear por exposición**:

- **Fase A (interno, hoy):** **mTLS del mesh** (OpenShift ya trae SPIFFE/cert-manager)
  como control **primario** + credenciales de backend de mínimo privilegio +
  NetworkPolicy (ya). Cierra el gap "cualquier llamante hereda las creds del backend"
  de forma proporcional, **sin** secretos compartidos que custodiar ni canonicalización
  SigV4. Nota: SigV4 obliga al gateway a **guardar los secret access keys de los
  clientes** (para el HMAC) → se vuelve un almacén de secretos = objetivo; mTLS (clave
  pública) lo evita.
- **Fase B (exposición / multi-tenant / terceros):** SigV4 + authz por
  bucket/prefix/tenant, exactamente como describe este ADR. **El ADR del equipo ES la
  Fase B**; solo proponemos no construirla entera si el despliegue aún no la necesita.

El ADR ya contempla "SigV4 sin mTLS como etapa de rollout"; para el caso interno
**invertimos el orden** (mTLS primero).

**Input 2 — capas y CLPE2.** Cuando exista authz por principal→tenant, la comprobación
de tenant del gateway y el AAD de CLPE2 (atado a ruta) pasan a ser **defensa en
profundidad bajo la authz** (la authz es el control primario de aislamiento;
CLPE2/AAD atrapan errores/bypass). El punto 6 de §Objetos ya lo respeta.

**Input 3 — alcance del AAD (cierra IR-02).** Recomendación de los mantenedores:
**AAD = `objectKey` únicamente, NO `bucket`**. Motivos: (a) el despliegue es
efectivamente single-bucket por config → el replay cross-bucket no está en el modelo
de amenaza; (b) atar el bucket añade acoplamiento **frágil** — productor y consumidor
deben coincidir en la cadena EXACTA del bucket, y el appender sube directo a S3
mientras el gateway proxea (el nombre de bucket podría divergir → fallos de descifrado
espurios). La 3ª opción ("identificador lógico estable") se descarta por complejidad
(habría que derivar el mismo ID lógico en ambos lados; más frágil que la key física).
Se cierra **ahora** que no hay datos CLPE2 persistentes; si el despliegue se vuelve
multi-bucket con movimiento entre buckets como riesgo real, se añade en CLPE3/flag.
Detalle del formato: `clp-log-tier/docs/superpowers/specs/2026-07-25-clpe2-aad-binding-design.md`.

## Referencias internas

- [`../deployment-security.md`](../deployment-security.md)
- [`../s3-api-contract.md`](../s3-api-contract.md)
- [`../security-review-2026-07-25.md`](../security-review-2026-07-25.md)
- [`../integration-review-2026-07-25.md`](../integration-review-2026-07-25.md)

## Referencias externas

- [AWS: Create a signed AWS API request](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
- [AWS: Troubleshoot Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-troubleshooting.html)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705.html)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449.html)
