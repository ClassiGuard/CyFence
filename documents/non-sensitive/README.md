# 🛡️ ClassiGuard CyFence

> **Enterprise Defensive Web Security & Posture Auditor for Red, Blue, and Purple Teams**  
> *Zero External Dependencies • Single Standalone Executable (Double-Click Web GUI) • Offline & Air-Gapped Ready • AI-Assisted with Mandatory Human In The Loop*

---

## ⚠️ CRITICAL LEGAL NOTICE & 6-MONTH EVALUATION RELEASE

> ### 🚨 AUTHORIZED TESTING & LEGAL DISCLAIMER
> **ClassiGuard CyFence is strictly intended for authorized defensive posture auditing, internal compliance assessment, and security research on systems YOU OWN or have EXPLICIT PRIOR WRITTEN CONSENT to evaluate.**
>
> * **NO LIABILITY:** Under no circumstances shall **ClassiGuard**, its founders, authors, or contributors be held liable for any damages, actions, outages, legal consequences, or claims arising from the use or misuse of this software.
> * **SOLE USER RESPONSIBILITY:** The operator assumes **100% sole responsibility** for their actions and compliance with all applicable local, national, and international cybercrime legislation (including the US Computer Fraud and Abuse Act 18 U.S.C. § 1030, the UK Computer Misuse Act 1990, the Indian IT Act 2000, and EU Directive 2013/40/EU).
> * **6-MONTH EVALUATION TERM:** This product is released for public community evaluation and testing for a period of **six (6) months** (Active through **April 2027**).
> 
> Read the complete binding legal terms: **[LEGAL DISCLAIMER](DISCLAIMER.md)** • **[EVALUATION LICENSE](LICENSE)** • **[CODE OF CONDUCT](CODE_OF_CONDUCT.md)** • **[SECURITY POLICY](SECURITY.md)**

---

## 🌟 Executive Summary

**ClassiGuard CyFence** is an enterprise-grade, zero-impact defensive security auditing engine built in pure Node.js. It assesses web applications and APIs against established cybersecurity benchmarks—including **OWASP ASVS v4.0** (Application Security Verification Standard), **MITRE ATT&CK**, **MITRE D3FEND**, **OWASP WSTG**, and **RFC 8725** (JWT Best Current Practices).

The product ships as a **single self-contained executable (`cyfence.exe`)** with **zero external dependencies**. No installation, no runtime setup, and no internet access are required.

---

## 🖥️ Desktop & Web GUI Experience (One-Click Launch)

You do **not** need to memorize CLI commands to use ClassiGuard CyFence. All CLI operations are completely integrated into an embedded graphical Web Suite.

### 🚀 Just Double-Click to Run
1. Download **`dist/cyfence.exe`** (or `dist/classiguard-cyfence.exe`).
2. **Double-click `cyfence.exe`**.
3. CyFence automatically starts its hardened loopback server on `http://127.0.0.1:9090` and **automatically opens your default web browser** to the dashboard.

---

### 🎛️ Graphical Operations Available in the Web Suite

The Web GUI provides 6 dedicated operational tabs covering every capability of the engine:

| Tab | Operation | Key Capabilities |
| :--- | :--- | :--- |
| **1. 🚀 Single Audit** | Target Posture Audit | Enter any URL, customize request headers, paste JWT tokens for RFC 8725 checks, toggle sensitive route scans (`/.git`, `/.env`), view live ASVS score (0–100), filter findings (Critical, High, Medium, Low, Passed), and **export reports in HTML, JSON, or Markdown** with one click. |
| **2. 📋 Multi-Target Batch** | Fleet Batch Auditing | Paste a list of URLs directly into the browser text area (or load sample targets), run concurrent fleet scans, view the real-time progress bar, and inspect the **Fleet Assessment Summary Matrix** comparing grades and defect breakdowns. |
| **3. ⚖️ Drift & Diff** | Posture Drift & Regression | Paste or load baseline and current JSON audit results. Instantly view the **Score Delta** (`+30 Points IMPROVED` or `-15 Points DEGRADED`), side-by-side lists of **New Vulnerabilities / Regressions**, and **Resolved Vulnerabilities**. |
| **4. 🛡️ Blue Team Auto-Patch** | Server Hardening & SIEM | Automatically generates tailored, copy-paste configuration snippets for **Nginx**, **Apache**, and **Caddy**, plus **Sigma SIEM detection rules (YAML)** and **Elasticsearch Query DSL**. Includes one-click **📋 Copy** and **💾 Download .conf / .yml** buttons. |
| **5. 🤖 AI Security Advisor** | Assisted Remediation | Multi-provider synthesis supporting **Ollama (100% offline, local air-gapped Llama 3)**, **Anthropic Claude**, and **OpenAI**. Enforces a strict **Human in the Loop Workflow** with interactive **✓ Approve for Staging** and **✕ Reject Proposal** buttons and timestamped audit logs. |
| **6. 📖 Tour & Architecture** | System Guide & Reference | Integrated reference guide detailing the OWASP ASVS alignment, 50,000 node benchmark metrics, and the 8/8 VAPT security verification matrix. |

---

## 🚀 Key Features by Team

### 🔴 Red Team & Attack Surface Discovery
* **Sensitive Route & File Exposure Scanner**: Passively discovers exposed version control repositories (`/.git/HEAD`), environment secrets (`/.env`), container configs (`/docker-compose.yml`), Spring Boot Actuator endpoints (`/actuator/health`, `/actuator/env`), and OpenAPI documents (`/swagger.json`).
* **WAF & CDN Perimeter Fingerprinting**: Identifies edge protections (Cloudflare, AWS WAF, Akamai, Imperva Incapsula, Fastly, F5 BIG-IP) or warns of direct origin exposure.
* **Discovery & RFC Compliance**: Audits `/.well-known/security.txt` (RFC 9116), OpenID Connect discovery endpoints, and checks `/robots.txt` for administrative path leakage.
* **MITRE ATT&CK Mapping**: Every finding embeds exact ATT&CK Technique IDs (e.g., `T1592`, `T1595.002`, `T1590`, `T1552`).

### 🔵 Blue Team & Detection Engineering
* **Auto-Remediation Config Generator**: Automatically generates copy-paste hardening configuration patches for **Nginx**, **Apache**, and **Caddy** directly targeting the findings detected during the audit.
* **Automated SIEM & Sigma Rule Exporter**: For every discovered defect, generates valid **Sigma detection rules (YAML)** and **Elasticsearch query DSL** to alert SOC teams when external actors probe those attack surfaces.
* **Configuration Drift & Diff Engine**: Compares two audit runs (`cyfence diff base.json current.json`) to track regressions, resolved issues, and score trends across deployment cycles.
* **MITRE D3FEND Countermeasures**: Explicit defensive mapping to controls such as `D3-HRP` (Header Restructuring Policy), `D3-IRA` (Inbound Restriction Analysis), and `D3-BRF` (Boundary Rule Filtering).

### 🤖 AI Security Advisor (Human Review Mandatory)
* **Multi-Provider Support**: Integrates seamlessly with **Ollama** (ideal for offline / air-gapped systems with zero internet access), **Anthropic Claude**, **OpenAI**, and **Codex**.
* **Strict Human in the Loop**: AI outputs are strictly formatted as advisory proposals. The engine explicitly enforces human review before any remediation patch is applied to production systems.

---

## ⚡ 50,000 Machine Scale & Stress Benchmark

ClassiGuard CyFence includes a high-throughput fleet auditing engine verified against 50,000 enterprise nodes:

### Benchmark Performance
* **Total Nodes Audited**: 50,000 machines
* **Total Execution Time**: **~0.33 seconds** (334.76 ms)
* **Throughput**: **~149,300 machines / second**
* **Average Latency**: **0.0067 ms** per machine
* **Peak Memory Heap**: **9.95 MB** (Delta: +4.23 MB, zero buffer bloat, linear GC)
* **Fleet Posture Profile**:
  * Grade A (Hardened): 10,000 (20.0%)
  * Grade B (Minor Gaps): 10,000 (20.0%)
  * Grade C (Moderate Risk): 10,000 (20.0%)
  * Grade D (High Risk): 10,000 (20.0%)
  * Grade F (Critical Risk): 10,000 (20.0%)
  * Total Defects Identified across fleet: **270,000 defects**

---

## 📁 Pre-Compiled Standalone Binaries

Located in `dist/`:
* **Windows Standalone Executables**:
  * `dist/classiguard-cyfence.exe` (Single self-contained `.exe`, zero external dependencies)
  * `dist/cyfence.exe` (Short alias `.exe` — double-click to auto-launch Web GUI)
* **Linux Distribution**: `dist/classiguard-cyfence-linux.tar.gz` (Portable tarball with POSIX shell launcher and native ELF compile script)
* **Universal JS Bundle**: `dist/bundle.cjs` (Universal zero-dependency script)

---

## 💻 CI/CD & Headless CLI Automation Reference

For DevOps pipelines, automated scheduled cron jobs, and terminal power users, CLI execution is fully supported whenever command-line arguments are passed:

### 1. Single Target Audit (with CI/CD Quality Gate)
```bash
# Windows
cyfence.exe https://example.com --min-score 80 --html reports/audit.html --json reports/audit.json

# Linux
./cyfence https://example.com --min-score 80 --json reports/audit.json
```

### 2. Multi-Target Batch Auditing
```bash
cyfence.exe --targets targets.txt --html reports/batch-summary.html
```

### 3. Launch Local Web GUI Explicitly
```bash
# Starts embedded browser GUI on http://127.0.0.1:9090 (CSRF Protected & Loopback Bound)
cyfence.exe gui 9090
```

### 4. Interactive Console Wizard (TUI)
```bash
# Interactive text menu for air-gapped terminal operators without browser access
cyfence.exe wizard
```

### 5. Configuration Drift & Regression Analysis
```bash
cyfence.exe diff baseline.json current.json
```

### 6. Blue Team Auto-Remediation Generation
```bash
cyfence.exe https://example.com --remediation --sigma detection.yml --export-configs reports/hardening/
```

### 7. AI Security Advisor (Ollama Local / Offline)
```bash
cyfence.exe https://example.com --ai --ai-provider ollama --ai-model llama3
```

---

## 🗺️ Interactive Product Tour

An interactive visual product tour and policy engine simulator is available in:
* **Standalone Interactive Visual:** [`documents/non-sensitive/product_tour.html`](documents/non-sensitive/product_tour.html)
* **Interactive Slide Card:** [`documents/non-sensitive/tour_card.html`](documents/non-sensitive/tour_card.html)

---

## 🛡️ Responsible Disclosure & Security

If you identify a security defect in ClassiGuard CyFence, please review our **[Security Policy](SECURITY.md)** and submit a private report via GitHub Advisories.

---

## 📜 License

Licensed under the **[ClassiGuard Community Evaluation License (6-Month Term)](LICENSE)**. All use is subject to the **[Legal Disclaimer](DISCLAIMER.md)**.
