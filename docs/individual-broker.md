# Individual-agent broker setup

`openuem-cert-manager individual-broker` initializes the separate service identities
and stock NATS configuration needed for individual desktop enrollment. It does not
change the legacy `generate-nats-conf.sh` deployment or generate any shared agent
identity. Reference deployment integration is still required.

```sh
openuem-cert-manager individual-broker \
  --directory /var/lib/openuem/broker-credentials \
  --name openuem-individual \
  --listen 127.0.0.1:4222 \
  --websocket-listen 127.0.0.1:9222 \
  --tls-cert /run/openuem/broker.pem \
  --tls-key /run/openuem/broker.key \
  --gateway-ca /run/openuem/gateway-ca.pem \
  --store-directory /var/lib/openuem/jetstream
```

Paths must be absolute. TLS/storage paths are interpreted by the eventual NATS
process; the command does not start NATS or claim those files are installed. Both
listeners must remain private. A container deployment can supply its private bind
addresses but must not publish these ports. The public gateway routes only the
approved WSS path to the backend and supplies its own client TLS certificate.

The directory contains these protected files:

| File | Recipient |
| --- | --- |
| `authorization-issuer.seed` | Authorization service only; signs bounded device grants |
| `authorization-user.seed` | Authorization service only; receives isolated callouts |
| `revocation-user.seed` | Revocation service only; requests active-session kicks |
| `worker-user.seed` | Individual agent worker only |
| `console-user.seed` | Console command publisher only |
| `provisioner-user.seed` | Fixed command-stream/consumer provisioning service only |
| `broker.json` | NATS configuration; contains only public service NKeys |

Retain the setup directory as protected provisioning material. Install only each
recipient's required files with that service's ownership; do not mount the entire
directory into every service. A readable copy of `broker.json` can be installed for
the NATS process because it contains no seed. Endpoint packages and public downloads
must never contain any of these service seeds.

On Unix, credential creation uses mode 0600 and exclusive creation. On Windows,
the file receives a protected DACL for the current user, LocalSystem and local
Administrators before any credential byte is written. Existing files and symlinks
are never overwritten. The setup command rejects unprotected or malformed existing
seeds and validates all five user keys are distinct.

The configuration is written last. If interrupted before then, rerunning with the
same parameters reuses valid existing seeds and completes missing files. Once
`broker.json` exists, every original seed must still exist; missing keys cause a
failure instead of silently replacing service identities. An unchanged rerun must
produce byte-identical configuration. Changed settings cause a conflict and require
a separate reviewed reconfiguration/rotation operation.

The command produces no secrets on stdout or in command-line arguments. It does
not replace organization enrollment CAs, Apple push credentials or public HTTPS
certificates. It pins the published shared-library commit `5083e68c8f76`, whose
[CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34172946043), including
native Windows credential creation/ACL checks and the actual NATS configuration test.

Run `go test ./internal/broker ./internal/commands` to verify protected creation,
partial setup recovery, unchanged retries, conflicting settings, missing installed
keys and CLI output. CI runs this on Linux and Windows, with Linux race checks.
