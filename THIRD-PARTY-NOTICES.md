# Third-party notices

| Component | License | Use |
|---|---|---|
| aws-sdk-go-v2 + smithy-go (AWS) | Apache-2.0 | compiled into the binary |
| golang (builder image) | BSD-3-Clause toolchain | build only |
| Red Hat ubi-micro | UBI EULA (redistribution permitted) | runtime base |

All permissive and MIT-compatible. The attached CycloneDX SBOM of each release
is the authoritative dependency inventory.

## Credits

- **[YScope](https://github.com/y-scope)** — creators of **CLP**, the compression
  and search engine this project family is built around (clp, clp-s, the JVM
  appenders, fluent-bit-clp, clp-ffi-*, yscope-log-viewer — all Apache-2.0).
- **Uber Engineering** — their CLP-in-production articles (*Reducing Logging Cost
  by Two Orders of Magnitude using CLP*, 2022, and *Modernizing Logging at Uber
  with CLP II*, 2024) are the origin of the deployment ideas this project
  implements (in-source compression, 16 MiB rollover, per-level flush deadlines).

The `CLPE` envelope name nods to CLP: this gateway was born to encrypt CLP log
archives end-to-end in [clp-log-tier](https://github.com/guigra/clp-log-tier).
