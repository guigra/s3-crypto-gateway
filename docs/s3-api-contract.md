# Contrato de API S3

`s3-crypto-gateway` implementa un subconjunto deliberado de la API S3
path-style. No es un reemplazo completo de un endpoint S3 y los clientes deben
limitarse a las operaciones descritas aquí.

## Operaciones soportadas

| Operación | Petición | Comportamiento |
|---|---|---|
| PutObject simple | `PUT /{bucket}/{key}` | Lee un objeto completo, lo cifra si aplica la política y lo escribe en el backend. |
| GetObject completo | `GET /{bucket}/{key}` | Lee y, si corresponde, descifra el objeto completo. |
| HeadObject | `HEAD /{bucket}/{key}` | Pasa la petición al backend. Para objetos CLPE1, tamaño y ETag corresponden actualmente al ciphertext. |
| DeleteObject | `DELETE /{bucket}/{key}` | Elimina el objeto en el backend. |
| ListObjectsV2 | `GET /{bucket}?list-type=2` | Soporta `prefix`, `continuation-token`, `delimiter` y `max-keys`. |
| Health check | `GET /healthz` | Endpoint propio del servicio; no forma parte de S3. |

El gateway conserva deliberadamente `ETag = MD5(plaintext)` en PutObject y
GetObject. Esta decisión no debe cambiarse sin estudiar la compatibilidad de
los clientes.

## Operaciones no soportadas

El gateway responde `501 NotImplemented` cuando detecta, entre otras:

- Range GET y respuestas parciales;
- peticiones condicionales;
- multipart upload;
- CopyObject;
- versionado mediante `versionId`;
- checksums S3 y validación de `Content-MD5`;
- operaciones mediante POST, incluido DeleteObjects;
- operaciones administrativas de bucket;
- ListObjects V1 y opciones ListObjectsV2 no implementadas;
- policies, lifecycle, CORS, restore y select;
- propiedades de objeto no preservadas, como `Content-Encoding`,
  `Content-Disposition`, `Cache-Control`, storage class, tagging o ACL;
- cabeceras SSE solicitadas por el cliente; SSE-C solo puede configurarse en el
  propio gateway para su conexión con el backend.

Las operaciones no deben ignorarse silenciosamente. Un método HTTP desconocido
recibe `405 MethodNotAllowed`; una función S3 conocida pero no implementada
recibe XML S3 con `501 NotImplemented`.

## Límites conocidos

- PUT y GET transforman el objeto completo en memoria y están sujetos a
  `MAX_OBJECT_BYTES`.
- HEAD y LIST no traducen actualmente tamaño o ETag del ciphertext a los del
  plaintext.
- Solo se admite direccionamiento path-style.
- PutObject conserva `Content-Type` y metadatos de usuario `X-Amz-Meta-*`; otras
  propiedades deben considerarse no soportadas.
- La compatibilidad depende tanto de las operaciones que use un cliente como de
  las cabeceras que añada automáticamente. Algunos SDK modernos activan
  checksums o multipart de forma automática y deben configurarse para no
  hacerlo.

Antes de declarar compatible un cliente, deben ejecutarse pruebas de contrato
con la versión y configuración concretas que se desplegarán.
