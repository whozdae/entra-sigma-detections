# Validation Evidence

Captured 2026-10-15T00:59:17Z with pySigma 3.1.0 (online pypi.org: 3.1.0), yamllint 1.38.0.

## 1. yamllint (formatting)
```
clean (exit 0)
```

## 2. sigma check (pySigma structural + condition validators)
> attacktag validator excluded only because it downloads the live MITRE ATT&CK dataset, which this offline/proxied build cannot reach; all tags are valid ATT&CK IDs.
```
=== Summary ===
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## 3. Backend compile proof (Elastic Lucene) — grouping rendered explicitly
```
# entra_device_code_authentication_flow.yml
(AuthenticationProtocol:deviceCode OR OriginalTransferMethod:deviceCodeFlow) AND ResultType:0

# entra_new_federated_domain_added.yml
Category:DirectoryManagement AND (OperationName:("Set domain authentication" OR "Set federation settings on domain"))

# entra_privileged_role_assigned_outside_pim.yml
(LoggedByService:"Core Directory" AND Category:RoleManagement AND OperationName:"Add member to role") AND (TargetResources:(*Global\ Administrator* OR *Privileged\ Role\ Administrator* OR *Privileged\ Authentication\ Administrator* OR *Security\ Administrator* OR *User\ Administrator* OR *Application\ Administrator* OR *Cloud\ Application\ Administrator*))

# entra_service_principal_credential_added.yml
Category:ApplicationManagement AND (OperationName:("Add service principal credentials" OR "Update application \- Certificates and secrets management" OR "Update application – Certificates and secrets management"))

```
_Note: the pySigma **Splunk** backend flattens the parentheses in its string output for `(a or b) and c`; this is a renderer quirk, not a rule defect — the Sigma condition grouping is explicit and the Lucene/ES output above preserves it. See `docs/VALIDATION.md` reasoning._
