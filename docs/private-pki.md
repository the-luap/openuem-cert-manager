# Private backend PKI initialization

`openuem-cert-manager private-pki` creates and verifies the private backend and
gateway TLS identities for the one-port reference installation. It generates the
CA and each service key locally, preserves exact identities on retry, and exports
separate service directories. It needs no OpenSSL command, database, network
access or existing certificate files.

This component covers backend PKI preparation. The complete reference composition,
first-administrator setup, administrator/device authorities, automatic private
certificate rotation and enterprise CA import remain separate work. Public TLS
uses the console repository's DNS-01 issuer; these private certificates are not
public HTTPS certificates or shared endpoint credentials.

## Initialize

Build the separate, pinned runtime:

```sh
docker build -f Dockerfile.private-pki --target runtime -t openuem-private-pki:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges openuem-private-pki:local private-pki --help
```

Provision a private initialization directory owned by UID/GID 65532 on the
deployment host. Its parent must already exist and be protected against writes
by unrelated users. The directory and its subdirectories must be mode 0700;
files must be regular mode-0600 files with one hard link, owned by the service UID
or root and readable by the initializer. The initializer does not change existing
permissions or recursively create host parents.

After selecting the directory, installation name and private DNS names:

```sh
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 128m \
  --mount type=bind,src=/srv/openuem/private-pki,dst=/state \
  openuem-private-pki:local private-pki --directory /state --name openuem \
  --console-dns console.internal --broker-dns nats.internal
```

Choose a stable lower-case installation name. Each DNS list accepts one to eight
distinct lower-case fully qualified names, supplied with repeated flags. Wildcards,
IP addresses, URL paths and ports are rejected. Console and broker names must be
distinct. Use these same names in the private gateway backend URLs and Docker
network aliases. The command normalizes list ordering before binding configuration.
Defaults are `openuem`, `console.internal` and `nats.internal`.

The native command is available on Linux and macOS. Windows deployment hosts use
the Linux container. Native Windows builds retain the existing certificate-manager
commands. The initializer opens no listener and installs nothing into host trust.

## Mount boundaries

Only start consumers after the initializer exits successfully. Its final
`manifest.json` identifies the ready installation, service certificate expiry and
SHA-256 hashes of every exported file. Do not start a service from a partial export.

| Directory | Contents and consumer |
| --- | --- |
| `authority/` | Backend CA certificate and private key; keep offline with initialization state |
| `gateway/` | Gateway client certificate/key and backend CA public certificate; gateway only |
| `console/` | Console/auth/MDM backend server certificate/key and exact gateway leaf trust |
| `broker/` | NATS backend server certificate/key and exact gateway leaf trust |
| `trust/` | Backend CA public certificate for private NATS service connections |

Mount each consumer's own directory read-only. The root `identity.json` contains
all original private keys and certificates; it is initialization/backup material,
never a runtime mount. The gateway must not receive `authority/`, the root state,
console/broker server keys, ACME account data or DNS provider credentials. Workers
receive only public backend trust and their separately initialized NKeys.

Wire the gateway's existing public certificate and routing configuration to:

```text
--gateway-cert /run/openuem-gateway/client.pem
--gateway-key /run/openuem-gateway/client.key
--backend-ca /run/openuem-gateway/backend-ca.pem
```

The console server certificate/key are `console/server.pem` and
`console/server.key`. Its exact gateway trust is `console/gateway-leaves.pem`,
selected with `OPENUEM_TRUSTED_GATEWAY_CERTIFICATES`. Configure its auth/Apple/
desktop/Windows listeners to use the generated server identity for the selected
private console DNS names. The RSA PKCS#1 console key is compatible with the
existing console configuration parser.

For the [individual broker initializer](individual-broker.md), use
`broker/server.pem`, `broker/server.key` and `broker/gateway-leaves.pem` as its
`--tls-cert`, `--tls-key` and `--gateway-ca` paths **inside the NATS container**.
Use the exact gateway leaf file for WebSocket client trust. Supplying the backend
CA there would broaden gateway admission to other certificates issued by that CA.
Device and service NKey authorization remains independent of gateway TLS.

Use console gateway commit `1f7a657c6c5a49ae5d296409ab13d372be4fb855` or later.
It explicitly selects the configured gateway certificate when a backend's TLS
issuer hints contain its pinned leaf subject. Signature/version checks and normal
server verification remain active. Earlier automatic Go certificate selection
could omit a CA-issued gateway leaf under this exact-leaf trust configuration.
[Gateway source](https://github.com/the-luap/openuem-console/commit/1f7a657c6c5a49ae5d296409ab13d372be4fb855).

The private backend CA is not an administrator or device enrollment authority.
It is not handed to the legacy certificate worker for issuing user certificates.
The gateway leaf permits client authentication only; console/broker leaves permit
server authentication only. The CA cannot issue subordinate CAs. Authority,
gateway and broker keys use P-256; the console key uses RSA-3072 for its existing
parser. Service leaves last one year and the backend root lasts ten years.

## Retry, failure and restore

A permanent directory lease excludes another initializer. `configuration.json`
binds a random installation identifier, creation time, name and normalized DNS
lists. Configuration changes are rejected on retry. Existing files, foreign
directories, symbolic links and broad permissions are never overwritten or fixed
silently.

Before the first service export, `identity.json` durably records the entire original
set of private keys and signed certificates. Export follows a fixed order and
syncs files and directory entries. A valid interrupted prefix can finish from that
same record, preserving exact certificate bytes as well as keys. A missing suffix
and lost readiness marker can be reconstructed from the retained original record;
no certificate is re-signed during that recovery. A hole followed by later files,
a missing key in a committed export, a missing identity record, inconsistent
manifest or corrupted file stops initialization. Unfinished private JSON records
are retained for explicit recovery, never treated as usable identities.

Back up the complete initialization root, including configuration, identity,
manifest, private authority and service directories. Restore it as a consistent
set with original ownership and permissions. Do not delete a marker or lease to
work around a failed check. Only the initializer receives writable access; runtime
containers receive their own read-only exports. Local Unix filesystems with atomic
file creation, native advisory locks and working file/directory fsync are required.
Network filesystems are outside the verified deployment.

SIGTERM/SIGINT cancels further generation/publication work. An interrupted export
can be retried with the same configuration. Expired identities cause a fixed error;
the command does not renew them behind running services or alter existing pins.
Monitor the manifest's expiry and use a planned certificate/pin overlap procedure
for rotation. The dedicated gateway and private backend rotation workflow is still
required for full PKI-01 acceptance.

## Verification

Unit/race tests verify actual mutual TLS using the generated console/broker
certificates and exact gateway leaf trust, direct-access denial, wrong hostname
and wrong-client rejection, existing console parser compatibility, exact retries,
interrupted export, original-identity recovery, missing/corrupt files, foreign data,
permissions, concurrent writers, root replacement, cancellation and expiry.

The separate smoke target runs the actual initializer and the actual pinned console
gateway against a local TLS backend. It verifies CA-issued gateway selection,
public device routing, external administration denial, shutdown, retry and missing
committed-key refusal. It contains no real CA account, provider or device.

Build the console's pinned gateway image first from a checkout of the source commit
above, then build and run this repository's smoke target:

```sh
docker build -f ../openuem/Dockerfile.gateway --target runtime \
  -t openuem-gateway:reference-test ../openuem
docker build -f Dockerfile.private-pki --target smoke -t openuem-private-pki-smoke:local .
docker run --rm --network none --add-host console.internal:127.0.0.1 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 96 --memory 256m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m openuem-private-pki-smoke:local
```

The [workflow](../.github/workflows/private-pki.yml) builds both source trees at
explicit revisions, runs native amd64/arm64 tests and requires an explicit fixture
pass rather than a skip. The distributed runtime is a separate scratch target,
UID/GID 65532, containing only the certificate-manager binary and license. It
exposes no port and contains no source, shell, gateway test binary or credentials.
