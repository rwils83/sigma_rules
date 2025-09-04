# Valid Inputs Reference for Sigma Rule Generator

This document lists controlled values and conventions that must be followed when generating rules.

---

## Status
Valid values:
- experimental
- test
- stable
- deprecated

---

## Level
Valid values:
- low
- medium
- high
- critical

---

## Tags
Tags must follow a **valid namespace**:
- `attack.` → MITRE ATT&CK techniques/tactics  
  - Examples: `attack.t1078`, `attack.initial_access`
- `cve.` → Common Vulnerabilities and Exposures  
  - Example: `cve.2021-44228`
- `car.` → MITRE Cyber Analytics Repository  
  - Example: `car.2016-04-005`
- `sigma.` → internal Sigma metadata or testing  
  - Example: `sigma.testing`

⚠️ Custom namespaces (like `info.` or `custom.`) will fail validation.

---

## Logsource
- **Windows Security**
  - product: `windows`
  - service: `security`
  - category: `account_change`, `password_change`, `authentication`, etc.
- **Windows Sysmon**
  - product: `windows`
  - service: `sysmon`
  - category: `process_creation`, `file_access`, `network_connection`, etc.
- **Apache**
  - product: `apache`
  - service: `access`
  - category: `webserver`

---

## Detection Keys
- **Windows**
  - `EventID`
  - `TargetUserName`
  - `SubjectUserName`
  - `LogonType`
- **Sysmon**
  - `Image`
  - `CommandLine`
  - `ParentImage`
  - `TargetFilename`
- **Web**
  - `request|contains`
  - `url.original`
  - `http.request.method`

---

