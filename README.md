# Sigma Rule Wizard

An interactive Python wizard for generating **Sigma rules** at scale — with UUIDs, presets (Windows Security, Sysmon, Apache), multiple selections (`sel_*`), validation, and clean YAML output.

## ✨ Features
- UUID v4 auto-generated for `id`
- Presets for **Windows Security**, **Windows Sysmon**, **Apache access** (or custom)
- Add **multiple selections** (e.g., `sel_eventid`, `sel_methods`, `sel_strings`)
- Set a custom **condition** (defaults to `sel_1 or sel_2 …`)
- Basic validation: status/level enums, condition references, at least one selection
- Writes spec-compliant YAML to `./rules/<slug>-<shortuuid>.yml`

---

## 🚀 Quick Start

### Requirements
- Python 3.8+
- `pyyaml`
- (Optional) Sigma CLI for lint/convert: `sigma-cli` and backends

### Install
```bash
# in your venv (recommended)
pip install pyyaml
# optional, for checking/converting rules
pip install sigma-cli pysigma-backend-elasticsearch pysigma-pipeline-windows pysigma-pipeline-sysmon
```

### Run the wizard
```bash
python rule_generator.py
```

You’ll be prompted for metadata, logsource, and any number of selections.  
Result is written to `./rules/`.

---

## 🧭 Usage Flow (what you’ll see)

1) **Title / Description / Author / Status / Level**  
2) **References, Tags, Fields, False positives** (comma-separated)  
3) **LogSource preset**  
   - 1) Windows Security → `product: windows`, `service: security`, choose `category`  
   - 2) Sysmon → `product: windows`, `service: sysmon`  
   - 3) Apache access → `product: apache`, `service: access`, `category: webserver`  
   - 4) Custom → enter your own  
4) **Selections** (loop)  
   - Add selection name (e.g., `sel_eventid`, `sel_methods`)  
   - Add one or more **field matchers**  
     Examples:  
     - Windows: `EventID` → values `4723,4724`  
     - Web: `request|contains` → values `GET,POST`  
   - Finish selection → leave **Field key** blank  
   - You’ll be asked **“Add another selection?”** — say `y` or `n`  
5) **Condition**  
   - Default is an `or` of all selection names (e.g., `sel_eventid or sel_methods`)  
   - Enter your own (e.g., `sel_methods and (sel_strings or sel_encoded)`)

---

## 🧪 Example (web)

Input sequence:
```
Preset: 3 (Apache)
Add selection? y
  name: sel_requests
  field: request|contains
  values: GET,POST
Add another selection? y
  name: sel_strings
  field: request|contains
  values: ../,%2e%2e%2f
Add another selection? n
Condition: sel_requests and sel_strings
```

Generated rule:
```yaml
title: Directory Traversal Attempt
id: 1f2e3d4c-1111-4222-8aaa-abcdefabcdef
status: experimental
description: Detects traversal via ../ or encoded variants in GET/POST.
references: []
author: Ryan Wilson
date: 2025-09-04
tags: []
logsource:
  product: apache
  service: access
  category: webserver
detection:
  sel_requests:
    request|contains:
      - GET
      - POST
  sel_strings:
    request|contains:
      - ../
      - %2e%2e%2f
  condition: sel_requests and sel_strings
fields: [request]
falsepositives: []
level: high
```

---

## ✅ Lint & Convert (Sigma CLI)

**Check:**
```bash
sigma check ./rules/<your-file>.yml
```

**Convert to Elastic Query String (KQL-style):**
```bash
# Windows rules
sigma convert -t es-qs -p windows ./rules/<file>.yml
# Web rules
sigma convert -t es-qs ./rules/<file>.yml
```

**Convert to Elasticsearch DSL JSON:**
```bash
sigma convert -t es-dsl -p windows ./rules/<file>.yml
```

---

## 🏷️ Tags (namespaces that pass lint)

Sigma enforces **namespaced tags**. Use only these roots:

- `attack.` (MITRE ATT&CK) — e.g., `attack.t1078`, `attack.initial_access`  
- `cve.` — e.g., `cve.2021-44228`  
- `car.` — e.g., `car.2016-04-005`  
- `os.` — e.g., `os.windows`, `os.linux`  
- `tool.` — e.g., `tool.apache`, `tool.mimikatz`  
- `malware.` — e.g., `malware.emotet`

> Tip: for internal/testing tags, prefer `tool.ecs_testing` or `os.windows` rather than inventing a new namespace.

---

## 🧹 Common Issues & Fixes

- **`SigmaIdentifierError`**  
  `id` must be a **UUID v4**. The wizard generates this automatically.

- **`InvalidNamespaceTagIssue`**  
  Tags must start with a valid namespace (see list above). Change `testing` → `tool.testing`.

- **`NumberAsStringIssue`**  
  Numeric values were quoted. Edit to integers:  
  `EventID: ["4723"]` → `EventID: [4723]`.

- **YAML scanner errors**  
  - Mixed tabs/spaces or unquoted `@`.  
  - Quote special fields like `@timestamp` → `"@timestamp"`.

- **CLI not found / import clashes**  
  Ensure the venv’s `bin` is on `PATH`. Avoid running inside a cloned `sigma/` repo directory that shadows imports.

---

## 🧩 Field Key Cheatsheet

- **Windows Security**: `EventID`, `TargetUserName`, `SubjectUserName`, `LogonType`  
- **Sysmon**: `Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `DestinationIp`  
- **Web (Apache)**: `request|contains`, `url.original`, `http.request.method`

> You can use Sigma operators in field keys, e.g., `request|contains`, `Image|endswith`, `CommandLine|contains`.

---

## 🗂️ Output

All rules are written to:
```
./rules/<slugified-title>-<shortuuid>.yml
```

---

## 🛠️ Roadmap Ideas
- Built-in templates (SQLi, traversal, webshell)  
- Tag namespace validation in the wizard  
- Batch mode (CSV/JSON → many rules)  
- Backend preview (run `sigma convert` and show query)

---

## 🤝 Contributing

1. Open a PR with changes to `rule_generator.py`  
2. Update **README.md** and **valid_inputs.md** if you change constraints  
3. Add example outputs to `examples/`  
4. Run:
   ```bash
   sigma check rules/*.yml
   ```
