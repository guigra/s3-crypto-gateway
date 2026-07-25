# Revisión de la integración de seguridad, S3 y CLPE2

- **Fecha:** 2026-07-25
- **Commit revisado:** `443bf12`
- **Resultado técnico:** build y suite correctos; política CLPE1 resuelta y
  alcance del AAD pendiente de confirmación explícita

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

### IR-01 — CLPE1 deja de ser legible — Resuelto

CLPE2 se implementó como reemplazo: el parser solo acepta versión 2. Un objeto
CLPE1 existente produce “versión no soportada”.

Producto confirma que CLPE1 no se mantendrá: no habrá lectura retrocompatible
ni migración desde v1. CLPE2 reemplaza a CLPE1 y es la única versión emitida y
aceptada.

Esta decisión supersede la condición histórica que pedía conservar
compatibilidad con CLPE1. El comportamiento actual del código es, por tanto, el
comportamiento aprobado. El despliegue no debe presentarse como capaz de leer
objetos CLPE1.

### IR-02 — El AAD liga key, no bucket — Resuelto (objectKey)

El AAD actual es exactamente el object key. Impide mover un ciphertext a otra
key, pero el mismo ciphertext puede copiarse a otro bucket conservando la misma
key y seguirá autenticando.

La comprobación de tenant del gateway sigue activa y el key suele contener el
tenant, lo que reduce el riesgo. Aun así, la decisión anterior contemplaba
autenticar contexto de ubicación, incluyendo potencialmente bucket.

DECIDIDO 2026-07-25: **solo `objectKey`** (no bucket). El replay cross-bucket queda fuera
del modelo de amenaza **siempre que single-bucket esté IMPUESTO** (ver precondición);
atar el bucket exige coincidencia byte-a-byte productor/consumidor (appender sube directo,
gateway proxea) con riesgo de fallos espurios. Opciones consideradas:

- solo `objectKey`, que facilita mover buckets completos;
- `bucket + objectKey`, que impide copias entre buckets;
- un identificador lógico estable independiente del almacenamiento.

Cambiar el AAD después de emitir objetos CLPE2 requiere versionado o una regla
de compatibilidad; por eso debe cerrarse antes de una release con datos
persistentes.

**Precondición (condición del equipo de seguridad, aceptada):** single-bucket NO está
impuesto por el gateway hoy. Debe imponerse con creds de backend limitadas por IAM a un
único bucket (inmediato) y/o `ALLOWED_BUCKETS` validado por el gateway (futuro). Si las
creds permiten varios buckets, el replay cross-bucket vuelve al modelo de amenaza →
trigger para CLPE3 (bucket+key). Ver `deployment-security.md`.

### IR-03 — Registro histórico desactualizado

`docs/security-review-2026-07-25.md` conserva correctamente el razonamiento
histórico, pero su cabecera y varios estados todavía describen Fases 1/2 y
CLPE2 como pendientes. También conserva como condición “no modificar CLPE1 de
forma incompatible”, decisión que el código integrado ha reemplazado.

Se recomienda actualizar el estado cuando producto confirme IR-02, sin borrar
las decisiones históricas. IR-01 ya está resuelto.

## Resultado

No se detectó una regresión de ejecución en la integración. El resultado es
apto para continuar revisión. IR-01 está resuelto por decisión de producto; la
release debe resolver explícitamente IR-02.
