# Frontera de confianza y despliegue seguro

## Advertencia

El gateway no autentica ni autoriza a sus clientes. No valida firmas SigV4. Toda
petición aceptada se vuelve a firmar con la identidad AWS configurada en el
servicio.

En consecuencia, cualquier proceso que alcance el puerto del gateway puede
ejercer los permisos S3 de esa identidad. El endpoint nunca debe publicarse
directamente mediante un LoadBalancer, NodePort o ingress accesible desde una
red no confiable.

## Controles mínimos

1. Aplicar una NetworkPolicy de entrada con selección explícita de namespaces y
   pods autorizados.
2. Usar credenciales S3 de mínimo privilegio, limitadas a los buckets y
   prefijos estrictamente necesarios.
3. Mantener TLS entre el gateway y el backend S3.
4. Si los clientes no comparten una frontera de red fiable, colocar delante un
   proxy con mTLS o autenticación y autorización equivalentes.
5. No registrar credenciales, KEK, claves SSE-C, cuerpos ni cabeceras
   criptográficas.

## NetworkPolicy incluida

`deploy/kubernetes/networkpolicy.yaml` selecciona pods con:

```yaml
app.kubernetes.io/name: s3-crypto-gateway
```

y solo permite tráfico TCP/9000 desde pods que tengan
`s3-crypto-gateway-access: "true"` dentro de namespaces que también tengan esa
etiqueta. Ambas etiquetas son necesarias.

Antes de aplicar el manifiesto:

- verificar que el Deployment usa el selector esperado;
- etiquetar únicamente namespaces y pods autorizados;
- adaptar el puerto si `PORT` no es 9000;
- comprobar el comportamiento de las sondas del clúster y del CNI;
- probar acceso permitido y denegado en un entorno no productivo.

La política solo controla ingress. El egress hacia S3 y DNS depende del backend,
puerto y controles de red de cada despliegue, por lo que debe definirse en la
plataforma que consume este proyecto.

SigV4 nativo queda fuera de esta fase y se mantiene como trabajo de
arquitectura posterior.
