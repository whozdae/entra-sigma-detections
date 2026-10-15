# SigmaHQ contribution package — Device Code Authentication Flow

This folder holds everything needed to submit the device-code rule to the upstream
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) repository. It is the one rule in this repo
verified as a genuine coverage gap at the time of writing.

---

## Why this rule (coverage gap)

SigmaHQ's `rules/cloud/azure/` tree has mature identity coverage — TAP added, Conditional Access
policy add/update/remove, MFA disabled, authentication-method changes, risk/MFA registration policy,
device-registration policy. It does **not** contain a rule for the **device code authentication
flow** in sign-in logs, despite device-code phishing being one of the most active Entra ID
initial-access techniques (Microsoft tracks the Storm-2372 campaign using exactly this flow).

Dup-check performed (2026-10-14):

- Searched `rules/cloud/azure/signin_logs/` and `rules/cloud/azure/audit_logs/` — no rule keys on
  `AuthenticationProtocol: deviceCode` or `OriginalTransferMethod: deviceCodeFlow`.
- Device-code detections exist publicly in **Splunk Research**, **Elastic**, and third-party rule
  sets, but **not** in SigmaHQ — i.e. the community standard repo is missing it.

If a reviewer points to an existing/overlapping rule, fold this logic in as an enhancement instead.

---

## Target path in the SigmaHQ repo

```
rules/cloud/azure/signin_logs/azure_signin_device_code_authentication_flow.yml
```

(Rename the local `rules/entra_device_code_authentication_flow.yml` to this on submission to match
SigmaHQ's `azure_signin_*` naming convention.)

## Proposed PR title

```
rules/cloud/azure: add Sign-In Using Device Code Authentication Flow
```

## Proposed PR description

> **Summary**
> Adds a new sign-in-logs rule detecting successful Entra ID sign-ins that completed through the
> OAuth 2.0 device authorization grant (device code flow). Device code flow is abused in phishing
> (e.g. Storm-2372) to capture access/refresh tokens while the victim authenticates on a genuine
> Microsoft page.
>
> **Detection**
> Matches `AuthenticationProtocol: deviceCode` or `OriginalTransferMethod: deviceCodeFlow`, gated on
> `ResultType: 0` (successful sign-in).
>
> **ATT&CK**
> T1078.004 (Valid Accounts: Cloud Accounts), T1566 (Phishing); tactics initial-access,
> credential-access.
>
> **Coverage**
> No existing `cloud/azure` rule keys on the device code flow (checked signin_logs and audit_logs).
>
> **False positives**
> Documented in the rule: genuinely input-constrained devices and intentional headless CLI/PowerShell
> device-code auth — baseline and allow-list.
>
> **Validation**
> `sigma check` clean; converts on the Splunk and Elasticsearch/Lucene backends; unit-tested against
> true-positive and benign sign-in fixtures.

---

## Submission steps (run on your machine, under your GitHub account)

```bash
# 1. Fork SigmaHQ/sigma on github.com, then:
git clone https://github.com/whozdae/sigma.git
cd sigma
git checkout -b rule-azure-device-code-flow

# 2. Copy the rule into place with SigmaHQ's naming convention
cp <this-repo>/rules/entra_device_code_authentication_flow.yml \
   rules/cloud/azure/signin_logs/azure_signin_device_code_authentication_flow.yml
#    update the `id:` only if you want a fresh UUID; keep author: Alex Adewoyin

# 3. Validate exactly as SigmaHQ CI does (network available => attacktag works)
pip install sigma-cli
sigma check rules/cloud/azure/signin_logs/azure_signin_device_code_authentication_flow.yml

# 4. Commit and push
git add rules/cloud/azure/signin_logs/azure_signin_device_code_authentication_flow.yml
git commit -m "rules/cloud/azure: add Sign-In Using Device Code Authentication Flow"
git push origin rule-azure-device-code-flow

# 5. Open the PR against SigmaHQ/sigma:main using the title/description above.
```

> Note: SigmaHQ reviewers may ask for `status: test` instead of `experimental`, a tweak to
> false-positive wording, or to align fields if the Event Hub taxonomy PR (#5993) lands first. That
> back-and-forth is normal and is itself the contribution experience worth having.
