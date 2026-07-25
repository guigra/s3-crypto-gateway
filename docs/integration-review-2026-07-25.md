# Revisión de la integración de seguridad, S3 y CLPE2

- **Fecha:** 2026-07-25
- **Commit revisado:** `443bf12`
- **Resultado técnico:** build y suite correctos; decisiones de migración y AAD
  pendientes de confirmación explícita

## Alcance integrado

El `main` revisado contiene:

- límites de objetos y timeouts HTTP;
- configuración SSE-C fail-closed;
- parser CLPE resistente a entradas truncadas y fuzzing;
- errores sanitizados;
- contrato S3 explícito y NetworkPolicy;
- Range sobre plaintext, condiciones ETag y checksums PUT;
- CLPE2 interoperable Java→Go con AAD.

El merge conserva el orden lógico de las ramas y no presenta cambios sin
commit.

## Validaciones ejecutadas

- build de la etapa Go;
- build completo de la imagen runtime UBI micro;
- `go vet ./...`;
- `go test ./...`;
- `go test -race ./...`;
- fuzzing de `Decrypt`: más de 800.000 ejecuciones sin panic;
- vector CLPE2 generado por Java descifrado por Go;
- `govulncheck ./...`: ninguna vulnerabilidad conocida encontrada;
- `git diff --check`;
- revisión de que las ramas auxiliares eran ancestros de `main`.

Estas comprobaciones no sustituyen una migración ensayada con objetos CLPE1 ni
pruebas end-to-end contra el backend S3 productivo.

## Observaciones que requieren decisión

### IR-01 — CLPE1 deja de ser legible

CLPE2 se implementó como reemplazo: el parser solo acepta versión 2. Un objeto
CLPE1 existente produce “versión no soportada”.

Esto contradice la decisión anterior que pedía lectura retrocompatible y
migración coordinada. Puede ser correcto si no existen objetos CLPE1 que deban
conservarse o si se ejecutará una migración completa antes del despliegue.

Antes de release debe elegirse y probarse una opción:

1. confirmar que no existen datos CLPE1 persistentes;
2. migrarlos con una herramienta y procedimiento verificables; o
3. añadir lectura CLPE1 temporal, manteniendo emisión exclusiva de CLPE2.

No debe desplegarse suponiendo retrocompatibilidad: el código actual no la
ofrece.

### IR-02 — El AAD liga key, no bucket

El AAD actual es exactamente el object key. Impide mover un ciphertext a otra
key, pero el mismo ciphertext puede copiarse a otro bucket conservando la misma
key y seguirá autenticando.

La comprobación de tenant del gateway sigue activa y el key suele contener el
tenant, lo que reduce el riesgo. Aun así, la decisión anterior contemplaba
autenticar contexto de ubicación, incluyendo potencialmente bucket.

Debe decidirse si el dominio de identidad del objeto es:

- solo `objectKey`, que facilita mover buckets completos;
- `bucket + objectKey`, que impide copias entre buckets;
- un identificador lógico estable independiente del almacenamiento.

Cambiar el AAD después de emitir objetos CLPE2 requiere versionado o una regla
de compatibilidad; por eso debe cerrarse antes de una release con datos
persistentes.

### IR-03 — Registro histórico desactualizado

`docs/security-review-2026-07-25.md` conserva correctamente el razonamiento
histórico, pero su cabecera y varios estados todavía describen Fases 1/2 y
CLPE2 como pendientes. También conserva como condición “no modificar CLPE1 de
forma incompatible”, decisión que el código integrado ha reemplazado.

Se recomienda actualizar el estado cuando producto confirme IR-01 e IR-02, sin
borrar las decisiones históricas.

## Resultado

No se detectó una regresión de ejecución en la integración. El resultado es
apto para continuar revisión, pero una release con datos reales debe quedar
bloqueada hasta resolver explícitamente IR-01 e IR-02.
