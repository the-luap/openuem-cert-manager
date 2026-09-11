# Retained individual broker configuration upgrade

`openuem-cert-manager individual-broker-upgrade` upgrades the preceding generated
worker grants to include `software` and, where absent, `hardware`, `recovery`
and `rotation`. It runs offline on Linux/macOS. It preserves all six service identities, listener addresses, TLS
references, account boundaries and the JetStream storage path. It never creates a
missing service key, starts NATS, signals a process or contacts a device.

This migration recognizes the exact configuration generated with shared-library
revisions `5083e68c8f76` (eight operations) and `87aa1bdf56ea` (eleven operations),
and the current `de9cd6f67c5e` renderer (twelve operations). The two preceding
initializer distributions are `938ea1a77eba4c9eb4517db629fc42ef2f8b96ad` and
`633bc7bb0dc34c1240a72a9df25c74ad19451885`. Unknown/custom permission changes,
formatting changes, duplicate JSON fields and different generated contracts are
rejected. This is a specific supported migration, not a general configuration
editor or key rotation command.

## Preview and apply

Use the existing private provisioning directory under a trusted parent. A preview
reads the retained configuration and verifies its public keys against all six
protected seeds. It creates no lock, journal, backup or replacement file:

```sh
openuem-cert-manager individual-broker-upgrade \
  --directory /var/lib/openuem/broker-credentials --check
```

The JSON result contains `version`, `before_sha256`, `after_sha256`,
`change_required` and `added_worker_requests`. Version 2 adds either `software`
alone or `hardware`, `recovery`, `rotation`, `software`, in that order. Review the
additional worker requests and retain the exact `before_sha256`. No seed or
configuration contents are printed.

During the deployment's maintenance procedure, stop the broker, then apply the
reviewed change using that public hash:

```sh
openuem-cert-manager individual-broker-upgrade \
  --directory /var/lib/openuem/broker-credentials \
  --expected-sha256 <before_sha256-from-preview>
```

Start the broker with its existing JetStream volume and unchanged service keys,
and verify authenticated readiness and consumer reconciliation before returning
the deployment to service. When `broker.json` is a single-file container bind
mount, verify that the mounted file matches `after_sha256`; remount or recreate
the broker if the runtime still exposes the old file. Bind mount behavior across
atomic replacement depends on the container runtime. A reload signal alone does
not prove that the process read the new configuration. The command does not
perform container orchestration, prove an installed broker is stopped or
configure host firewall rules.

The private PKI distribution image also includes this command. Run it offline,
non-root, with the existing provisioning directory as its only writable bind and
with a read-only root filesystem. Do not pass service seeds in environment
variables or arguments. Runtime services still receive only their own required
files; neither the broker nor endpoints receive the provisioning directory.

## Durable state

The command uses a directory lease and writes private files with exclusive
creation. It syncs each complete file and the containing directory. It stages the
full target configuration before an atomic rename over `broker.json`.

| File | Retention |
| --- | --- |
| `broker-upgrade.lock` | Private lease file; ownership and inode checked while held |
| `broker-upgrade-v2.json` | Immutable before/after hash journal |
| `broker-before-v2.json` | Exact original configuration; retained after success |
| `broker-next-v2.json` | Fully written target staging file; consumed by publication |
| `broker-upgrade-v2.complete.json` | Completion marker after publication and directory sync |

Completed v1 journal, backup and completion files are verified against the exact
eight-to-eleven-operation migration and retained unchanged. Version 2 uses
separate files and retains the eleven-operation configuration as its own backup.
An interrupted v1 migration must first be resumed with its original pinned
`633bc7bb0dc34c1240a72a9df25c74ad19451885` distribution and original reviewed hash.
The new command rejects incomplete, damaged or rolled-back v1 history without
rewriting it or consuming its staging file.

A retry with the original reviewed hash verifies these records and resumes a
completed-write interruption, including interruption after the configuration
rename. A missing completion marker can be recreated only with the intact journal,
backup and exact target configuration. A fresh preview of an already completed
upgrade can also be applied as an unchanged verification.

Missing committed backup/journal files, partial writes, inconsistent records,
changed service identities, a rolled-back active configuration and unsafe
permissions fail without replacement or regeneration. An interrupted staging
file is retained for investigation; the command does not truncate it and retry.
Competing upgrades must retry after the current directory lease is released.
A service that bypasses the lease or modifies ancestor directories is outside
the supported provisioning contract; keep those directories trusted.

The original `individual-broker` command still never rewrites conflicting
configuration. After this migration succeeds, an identical current initialization
retry accepts the upgraded configuration and retains the same identities.

## Verification

Unit and CLI tests cover the exact permission delta, unchanged settings and keys,
read-only preview, review hash checks, interruption after each completed write
and publication, damaged journal/backup/staging state, rollback detection,
concurrency, cancellation and mutation before publication.

`Dockerfile.broker-upgrade-test` is an isolated acceptance image, separate from
the distribution. It runs the actual previous initializer, current upgrade
command and stock NATS 2.14.6 executable. The old broker denies the missing worker
subject. It stores a command message and durable consumer on disk, stops cleanly,
then starts with the upgraded configuration. It covers the original eight-operation
initializer, the eleven-operation initializer, and an actual completed v1 upgrade.
The fixture verifies the software subscription and all other added subscriptions,
continued rejection of a broader wildcard, unchanged service seeds, the retained message/consumer and subsequent command delivery into the
same pending consumer. It requires an explicit passing process test; missing
binary inputs cannot silently skip it.

Local validation of the twelve-operation migration passed the broker, CLI and
private-PKI race suites, vet, Windows amd64 and Linux amd64 builds, and all three
actual distribution scenarios in an unprivileged offline Linux arm64 container.
This includes current initialization and v2 interruption/retry tests for both
preceding grants, plus rejection of incomplete v1 history and custom grants.

The native Linux amd64/arm64 workflow pins all historical source revisions and
runs this fixture with no network access, published ports, root privileges or
external state. These are synthetic local broker checks. Complete reference
upgrade orchestration, full backup restoration and physical device acceptance
remain separate requirements.
