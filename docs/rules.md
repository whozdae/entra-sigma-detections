# Rule catalog — technique explainers

Four detections spanning the Entra ID identity attack chain: **initial access → persistence → privilege escalation → defense evasion.** Each rule is written to the current SigmaHQ `cloud/azure` taxonomy and unit-tested against sample sign-in / audit-log events.

| # | Rule | Stage | Log source | ATT&CK | SigmaHQ coverage |
|---|------|-------|-----------|--------|------------------|
| 1 | Device code authentication flow | Initial Access | `signinlogs` | T1078.004, T1566 | **gap — submitted** |
| 2 | Service principal / app credential added | Persistence | `auditlogs` | T1098.001 | partial |
| 3 | Privileged role assigned outside PIM | Priv. Escalation | `auditlogs` | T1098.003 | adjacent (secops set) |
| 4 | New federated domain configured | Defense Evasion | `auditlogs` | T1484.002 | Entra gap (only m365/Exchange exists) |

---

## 1. Device code authentication flow — `entra_device_code_authentication_flow.yml`

**Technique.** The OAuth 2.0 device authorization grant lets an input-constrained device (TV, IoT) show a code the user types on a second device. Attackers abuse it (Storm-2372, 2025) by starting the flow and phishing the victim to complete it on the *real* Microsoft page — the attacker then receives the access and refresh tokens. No password or MFA prompt ever reaches the attacker; the victim hands over a live session.

**Log source & fields.** Entra sign-in logs. `AuthenticationProtocol: deviceCode` is the classic signal; newer logs also expose `OriginalTransferMethod: deviceCodeFlow`. The rule matches either, gated on `ResultType: 0` (successful sign-in only).

**Why it's high-signal.** Almost no legitimate corporate workflow uses device code flow from a normal user endpoint. Baseline the handful of apps/users that do, allow-list them, alert on the rest.

**False positives.** Genuine input-constrained hardware; deliberate CLI/PowerShell device-code auth on headless hosts.

## 2. Service principal / application credential added — `entra_service_principal_credential_added.yml`

**Technique.** An attacker who compromises a privileged identity adds their *own* client secret or certificate to an existing (often highly privileged) application or service principal. They then authenticate as that application — non-interactively, with no MFA and no Conditional Access on the user — for durable, quiet access. This is the mechanism behind AADInternals-style persistence.

**Log source & fields.** Entra audit logs. `Category: ApplicationManagement` with `OperationName` in *Add service principal credentials* / *Update application – Certificates and secrets management* (both en-dash and hyphen variants matched).

**False positives.** Legitimate secret/certificate rotation by app owners or CI/CD. Correlate with change management and known automation accounts.

## 3. Privileged role assigned outside PIM — `entra_privileged_role_assigned_outside_pim.yml`

**Technique.** In a PIM-governed tenant, privileged access is expected to be *eligible* and time-bound. A standing (permanent, active) assignment to a role like Global Administrator made directly by **Core Directory** — rather than a **PIM** activation — either bypasses governance or is an attacker granting themselves durable privilege.

**Log source & fields.** Entra audit logs. `LoggedByService: Core Directory` + `Category: RoleManagement` + `OperationName: Add member to role`, scoped to a watch-list of privileged role names via `TargetResources|contains`. PIM activations (logged by service `PIM`) are deliberately excluded — that exclusion is what the benign PIM-activation fixture proves.

**False positives.** Approved break-glass or deliberately-permanent admin provisioning. Allow-list break-glass accounts; reconcile with change records.

## 4. New federated domain configured — `entra_new_federated_domain_added.yml`

**Technique.** With enough directory privilege, an attacker federates a domain to an IdP they control (or alters token-signing/federation settings) and forges SAML tokens to sign in as *any* user — "Golden SAML" / domain-trust modification, as seen in the SolarWinds intrusion.

**Log source & fields.** Entra audit logs. `Category: DirectoryManagement` + `OperationName` in *Set domain authentication* / *Set federation settings on domain*.

**Coverage note.** SigmaHQ covers the federated-domain change in the **m365 / Exchange unified audit log** taxonomy, but not in the native `cloud/azure` Entra audit-log taxonomy — this rule fills that representation.

**False positives.** Planned ADFS / third-party IdP migrations. Confirm against change management and the expected administrator.
