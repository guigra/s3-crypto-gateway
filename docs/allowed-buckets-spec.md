# Spec de implementación: `ALLOWED_BUCKETS` (control en el gateway)

- **Estado:** implementado en `feature/allowed-buckets`
- **Origen:** precondición de la decisión AAD=objectKey (CLPE2) — condición 1 del
  equipo de seguridad. Ver `integration-review-2026-07-25.md` §IR-02,
  `deployment-security.md` y `docs/adr/0001-inbound-authentication-and-authorization.md`.

## Por qué

La decisión CLPE2 (AAD = solo `objectKey`) es segura **siempre que single-bucket esté
impuesto**. La restricción IAM del backend es el control inmediato; `ALLOWED_BUCKETS` es
el control **en el propio proceso** (defensa en profundidad, y protege aunque las creds
IAM sean más amplias de lo debido). Sin al menos uno de los dos, el replay cross-bucket
vuelve al modelo de amenaza.

## Contrato

- **Config:** nueva variable `ALLOWED_BUCKETS` (CSV de nombres de bucket permitidos).
  - **vacía = sin restricción** (compat; se confía en el control IAM). Documentar que la
    precondición exige que esté puesta **o** que las creds IAM limiten a un bucket.
  - **no vacía = allowlist estricta**: solo esos buckets; cualquier otro se rechaza.
  - Parseo con el helper `splitCSV` existente; nombres con `TrimSpace`.
- **Punto de aplicación:** en `handle()`, tras derivar `bucket` de la ruta y **antes** de
  despachar a put/get/head/del/list (aplica a TODAS las operaciones, incluida LIST).
- **Respuesta al rechazo:** `403 AccessDenied` con mensaje genérico (no revelar la lista).
  Reutilizar `s3err`. Evitar filtrar si el bucket existe o no.
- **Fail-closed de config:** `ALLOWED_BUCKETS` malformado (p. ej. solo comas/espacios que
  quede efectivamente vacío cuando se pretendía restringir) no debe degradar silenciosamente;
  seguir el patrón de `loadConfig() (Config, error)` de SSE-C (fallar al arrancar ante
  configuración inválida). Un valor vacío legítimo (sin restricción) es válido.

## Pruebas

- bucket en la allowlist → pasa (PUT/GET/HEAD/DELETE/LIST).
- bucket fuera de la allowlist → `403 AccessDenied` en todas las operaciones.
- `ALLOWED_BUCKETS` vacío → sin restricción (compat).
- interacción con el contrato S3 existente: el orden de validación no debe permitir que una
  operación no soportada de un bucket no permitido se cuele (probar ambos filtros juntos).
- config: valor válido arranca; valor inválido falla al arrancar.

## Documentación actualizada

- Tabla de config del `README.md`.
- `docs/s3-api-contract.md`.
- `docs/deployment-security.md`.
- `integration-review` §IR-02.
