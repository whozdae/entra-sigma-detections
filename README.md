# Entra ID Detection-as-Code — Sigma rules, tested in CI

![Sigma](https://img.shields.io/badge/Sigma-detection--as--code-1f6feb)
![Platform](https://img.shields.io/badge/Entra%20ID-sign--in%20%2B%20audit%20logs-0078D4)
![Tested](https://img.shields.io/badge/tested-19%2F19%20fixtures-brightgreen)
![Validated](https://img.shields.io/badge/pySigma-0%20issues-brightgreen)
![CI](https://img.shields.io/badge/CI-yamllint%20%2B%20sigma%20check%20%2B%20pytest-6A1B9A)

> I wrote four Microsoft Entra ID (Azure AD) detection rules in **Sigma**, mapped them across the
> identity attack chain, and treated them as *code* — every rule is linted, validated with pySigma,
> compiled to real SIEM query languages, and unit-tested against sample log events so I can prove it
> **fires on the malicious event and stays silent on the benign one.** One rule — device code
> authentication flow — is a verified gap in the upstream SigmaHQ repo and is packaged as a pull
> request.

| | |
| :-- | :-- |
| **What** | 4 Sigma detections for Entra ID sign-in & audit logs, across the identity kill chain |
| **Discipline** | Detection-as-code: lint → validate → backend-compile → unit-test, in CI |
| **Result** | pySigma: **0 issues**; tests: **19/19** fixtures (8 true-positive fire, 11 benign silent) |
| **Contribution** | 1 rule verified as a SigmaHQ coverage gap, PR-ready |
| **Skills** | Sigma, detection engineering, Entra ID / IAM telemetry, MITRE ATT&CK, pySigma, CI, Python |

---

## Why this exists

Most "detection" portfolios are a folder of untested YAML. In a real detection-engineering or SOC
shop, a rule you can't *test* is a liability — it either misses the attack or drowns the analyst in
false positives. So this repo is built the way detection-as-code is supposed to work: the rules sit
next to sample logs and a test harness that enforces both halves of a good detection — **true
positives fire, benign activity doesn't** — and the whole thing runs in CI on every push.

The rules are deliberately **identity-focused** (Entra ID / IAM), covering one technique at each
stage of an identity intrusion.

## The four detections

| # | Rule | Kill-chain stage | Log source | ATT&CK |
|---|------|-----------------|-----------|--------|
| 1 | [Device code authentication flow](rules/entra_device_code_authentication_flow.yml) | Initial Access | `signinlogs` | [T1078.004](https://attack.mitre.org/techniques/T1078/004/), T1566 |
| 2 | [Service principal / app credential added](rules/entra_service_principal_credential_added.yml) | Persistence | `auditlogs` | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) |
| 3 | [Privileged role assigned outside PIM](rules/entra_privileged_role_assigned_outside_pim.yml) | Priv. Escalation | `auditlogs` | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) |
| 4 | [New federated domain configured](rules/entra_new_federated_domain_added.yml) | Defense Evasion | `auditlogs` | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) |

Full technique write-ups: [`docs/rules.md`](docs/rules.md).

## How they're tested

Each rule ships with two fixtures: `*.tp.json` (events that **must** fire) and `*.benign.json`
(events that **must not**). The benign sets are built to exercise each rule's discriminating logic —
e.g. a *failed* device-code sign-in (proves the success gate), a *PIM activation* of Global Admin
(proves the non-PIM scoping), a matching operation under the *wrong category* (proves field
precision). A small dependency-light Sigma evaluator (`tests/evaluator.py`) runs the rule's real
`detection`/`condition` logic against every event.

```
$ python tests/test_rules.py
RULE                                                  TP  BENIGN  RESULT
--------------------------------------------------------------------------------
entra_device_code_authentication_flow                  2       3  PASS
entra_new_federated_domain_added                       2       2  PASS
entra_privileged_role_assigned_outside_pim             2       3  PASS
entra_service_principal_credential_added               2       3  PASS
--------------------------------------------------------------------------------
ALL TESTS PASSED
```

## How they're validated

- **yamllint** — formatting (clean).
- **`sigma check`** (pySigma) — rule structure, condition logic, ATT&CK tag validity → **0 errors,
  0 condition errors, 0 issues**.
- **Backend compile** — every rule converts cleanly to Splunk SPL and Elastic Lucene, proving the
  logic is portable to a real SIEM.

Captured evidence (with the one honest caveat about Splunk's parenthesis rendering):
[`docs/VALIDATION.md`](docs/VALIDATION.md). The same checks run in CI:
[`.github/workflows/validate.yml`](.github/workflows/validate.yml).

## The SigmaHQ contribution

SigmaHQ's `cloud/azure` coverage is mature, so I dup-checked each technique before claiming novelty.
The **device code authentication flow** rule is a genuine gap — device-code phishing (Storm-2372) is
a top Entra initial-access technique, detections exist in Splunk/Elastic, but SigmaHQ has none. It's
packaged for upstream submission — title, description, dup-check evidence and submit steps — in
[`pr/sigmahq-pr-device-code.md`](pr/sigmahq-pr-device-code.md). The other three are strong detections
that overlap existing SigmaHQ work to varying degrees; I've labelled the overlap honestly in
[`docs/rules.md`](docs/rules.md) rather than overclaiming.

## Usage

```bash
pip install -r requirements.txt

python tests/test_rules.py            # run the detection unit tests
sigma check rules/                    # pySigma validation
sigma convert -t lucene --without-pipeline rules/entra_device_code_authentication_flow.yml
```

## Repo structure

```text
entra-sigma-detections/
├── README.md
├── rules/                     # the 4 Sigma rules
├── tests/
│   ├── evaluator.py           # minimal Sigma condition evaluator
│   ├── test_rules.py          # fires-on-bad / silent-on-good harness (pytest + standalone)
│   └── logs/                  # *.tp.json (must fire) + *.benign.json (must not)
├── docs/
│   ├── rules.md               # per-rule technique explainers + ATT&CK + coverage honesty
│   └── VALIDATION.md          # captured lint / sigma-check / backend-compile evidence
├── pr/
│   └── sigmahq-pr-device-code.md   # upstream PR package for the gap rule
├── .github/workflows/validate.yml  # CI: yamllint + sigma check + pytest
├── requirements.txt
└── .gitignore
```

## Skills demonstrated

Detection engineering · Sigma rule authoring · detection-as-code / testing discipline · Microsoft
Entra ID (Azure AD) sign-in & audit telemetry · IAM attack techniques (device-code phishing, service
principal abuse, PIM bypass, Golden SAML) · MITRE ATT&CK mapping · pySigma validation & backend
conversion · CI (GitHub Actions) · Python.

---

*Built by Alex "Dae" Adewoyin. All rules test against synthetic, offline log fixtures — no real
tenant data is included.*
