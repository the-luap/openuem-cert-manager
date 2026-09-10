# OpenUEM - Cert Manager

Repository containing the OpenUEM certificate tools used to manage the project's certificates requirements. It contains the command-line tools to generate and the library that will be used from the OpenUEM console.

This repository will be used as a git submodule from other OpenUEM's repositories

The [private backend PKI initializer](docs/private-pki.md) creates and preserves
separate gateway, console and broker identities for the one-port reference
installation. [Individual broker setup](docs/individual-broker.md) initializes
its separately protected service NKeys and stock NATS configuration.

References:

- [OCSP RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960)
- [Revocation reasons](https://rfc-editor.org/rfc/rfc5280.html)
- [https://go.dev/src/crypto/tls/generate_cert.go](https://go.dev/src/crypto/tls/generate_cert.go)
- [https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251](https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251)
- [https://github.com/cloudflare/cfssl](https://github.com/cloudflare/cfssl)
- [https://stackoverflow.com/questions/61028110/with-golang-how-can-i-generate-a-rsa-certificates-then-export-the-private-key-to](https://stackoverflow.com/questions/61028110/with-golang-how-can-i-generate-a-rsa-certificates-then-export-the-private-key-to)
