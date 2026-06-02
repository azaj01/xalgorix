# External Secrets Operator + AWS Secrets Manager

This directory wires every long-lived production secret consumed by the
Cloud_Platform into Kubernetes through the [External Secrets Operator
(ESO)](https://external-secrets.io). AWS Secrets Manager is the source of
truth; ESO mirrors each secret into a native `Secret` object inside the
`xalgorix` namespace, where API_Server and Worker_Pool pods mount it as
files (per the **Secrets management** rule in `design.md`: no env vars
containing secrets except the platform-known `DODO_PAYMENTS_*`).

Implements task **14.5** and acceptance criteria **20.1** and **20.3**
of the `xalgorix-saas` spec.

## Layout

| File | Resource | Backing AWS Secrets Manager entry | Materialised Kubernetes `Secret` | Keys |
| --- | --- | --- | --- | --- |
| `secret-store.yaml` | `ClusterSecretStore/aws-secrets-manager` | n/a (binds the ESO ServiceAccount via IRSA) | n/a | n/a |
| `dodo.yaml` | `ExternalSecret/xalgorix-dodo` | `xalgorix/dodo` | `xalgorix-dodo` | `DODO_PAYMENTS_API_KEY`, `DODO_PAYMENTS_WEBHOOK_KEY` |
| `resend.yaml` | `ExternalSecret/xalgorix-resend` | `xalgorix/resend` | `xalgorix-resend` | `RESEND_API_KEY` |
| `oauth.yaml` | `ExternalSecret/xalgorix-oauth` | `xalgorix/oauth` | `xalgorix-oauth` | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` |
| `vapid.yaml` | `ExternalSecret/xalgorix-vapid` | `xalgorix/vapid` | `xalgorix-vapid` | `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY` |
| `jwt.yaml` | `ExternalSecret/xalgorix-jwt` | `xalgorix/jwt` | `xalgorix-jwt` | `JWT_SIGNING_KEY` (Ed25519 PEM) |

Every `ExternalSecret` declares:

- `refreshInterval: 1h` — ESO re-reads each backing entry hourly. A
  rotation pushed to AWS Secrets Manager is therefore in-cluster within
  one hour without any pod redeploy.
- `target.namespace: xalgorix` — all secrets land in the application
  namespace; pods reference them by name only.
- `target.template.metadata.labels` — `app.kubernetes.io/name`,
  `app.kubernetes.io/part-of: xalgorix`, `app.kubernetes.io/component:
  secret`, and `xalgorix.com/secret-source: aws-secrets-manager`. These
  are mirrored on the `ExternalSecret` itself so selectors work against
  either resource.
- `secretStoreRef.kind: ClusterSecretStore` pointing at
  `aws-secrets-manager` — the operator authenticates with IRSA, so no
  long-lived AWS access keys live in the cluster.

## Region templating

`secret-store.yaml` carries `region: ${AWS_REGION}`. The Kustomize
overlays (`infra/k8s/overlays/us-east-1`, `infra/k8s/overlays/eu-west-1`)
substitute the literal region at render time so the same source manifest
ships into both clusters unchanged. There is no cross-region replication
of secrets — each region has its own copies in its own AWS account.

## How a deploy uses these

1. ESO controller pod (in `external-secrets` namespace) holds the
   `external-secrets` ServiceAccount with an IRSA-bound IAM role that
   has `secretsmanager:GetSecretValue` and `kms:Decrypt` on the
   `xalgorix/*` secret ARNs and the KMS CMKs that protect them.
2. ESO reconciles each `ExternalSecret`, fetches the backing JSON object
   from AWS Secrets Manager, and writes a Kubernetes `Secret` of the
   same name into the `xalgorix` namespace.
3. API_Server and Worker_Pool pods mount the relevant `Secret` as a
   `projected` volume at `/var/run/secrets/<name>/`. No secret value is
   ever placed in an env var (the sole exception is the
   `DODO_PAYMENTS_*` set, which the Dodo SDK reads from env per the
   `BugReportly/lib/dodoPayments.js` pattern).

## KMS rotation policy (90-day)

Per **Requirement 20.1**, all customer data at rest is encrypted with
AES-256-GCM under AWS KMS keys that **MUST be rotated every 90 days**.
The same 90-day cadence applies to the KMS CMKs that protect the
secrets in this directory. The contract is:

| Item | Owner | Frequency | Mechanism |
| --- | --- | --- | --- |
| KMS CMK rotation for `xalgorix/dodo`, `xalgorix/resend`, `xalgorix/oauth`, `xalgorix/vapid`, `xalgorix/jwt` | Platform Security | every 90 days | AWS KMS automatic key rotation **and** a scheduled CI job (`security-rotation-90d.yml`) that calls `aws kms rotate-key-on-demand` and then `aws secretsmanager rotate-secret` for each backing entry |
| Re-encryption of secret payloads under the new KMS key version | AWS Secrets Manager | automatic | triggered by the same CI job; uses Lambda rotation functions for `xalgorix/dodo` (Dodo Payments key roll), `xalgorix/jwt` (Ed25519 keypair regeneration with 14-day overlap, see Decisions and Defaults #1), and `xalgorix/vapid` (Web Push keypair regeneration). `xalgorix/oauth` and `xalgorix/resend` use `RotationDisabled` because the upstream provider issues the credentials; the CI job opens a tracked rotation ticket instead. |
| In-cluster propagation | External Secrets Operator | automatic, ≤ 1 h | `refreshInterval: 1h` on every `ExternalSecret`. New secret versions are picked up on the next reconcile loop without any pod restart, because every `Secret` is mounted as a `projected` volume that the kubelet refreshes on update. |
| Audit | Cloud_Platform | every 90 days | `security-rotation-90d.yml` writes an `audit_event` of type `kms_key_rotated` per CMK and posts a summary to the `#sec-audit` channel. |

The schedule is anchored on the first Monday of each calendar quarter so
all five backing entries rotate in lock-step. A rotation that fails to
complete inside 24 hours pages Platform Security via PagerDuty.

## Adding a new secret

1. Create the entry in AWS Secrets Manager under `xalgorix/<name>` as a
   JSON object whose keys match the env-var-style names you want to
   surface in Kubernetes.
2. Add the matching IAM policy statement on the ESO IRSA role.
3. Drop a new `<name>.yaml` here, copying one of the existing
   `ExternalSecret` files. Keep `refreshInterval: 1h`, the
   `xalgorix` namespace, and the standard label set.
4. Add the new entry to the table at the top of this README and to the
   `security-rotation-90d.yml` CI workflow.
