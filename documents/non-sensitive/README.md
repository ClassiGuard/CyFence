# 🛡️ ClassiGuard CyFence

> **Enterprise Offensive & Defensive Web Security Posture & Compliance Suite**  
> *Single Self-Contained Executable (`cyfence.exe`) • Zero Runtime Dependencies • Native Desktop Application Window • 100% Offline & Air-Gapped Ready • BYOK AI Engine with Mandatory Human Approval*

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

## 🌟 Instant Quickstart: Single Executable (`dist/cyfence.exe`)

ClassiGuard CyFence is delivered as a **single, self-contained standalone binary with zero external dependencies**. No Node.js runtime, no Python, no external libraries, and no installers are required on the target machine.

```
               ┌────────────────────────────────────────────────────────┐
               │                  DOWNLOAD & DOUBLE-CLICK               │
               │                      dist/cyfence.exe                  │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │           AUTOMATIC DESKTOP GUI INITIALIZATION         │
               │  • Background server binds http://127.0.0.1:9090       │
               │  • Dedicated Desktop Window launches (Edge/Chrome App) │
               │  • Displays Real Host LAN/Wi-Fi IP alongside Loopback  │
               │  • Zero-configuration, zero setup, single executable   │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │       DEEP RED TEAM VAPT & POSTURE DEFENSE SUITE       │
               │  Active SQLi, XSS, SSRF, LFI, OpenAPI, AI & ASVS v4.0  │
               └────────────────────────────────────────────────────────┘
```

### 🚀 Running the Desktop Application
1. Download **[`dist/cyfence.exe`](dist/cyfence.exe)**.
2. Double-click `cyfence.exe`.
3. **What happens automatically:**
   * CyFence immediately starts its secure local air-gapped security engine on `127.0.0.1:9090`.
   * CyFence opens a **native desktop application window** (Edge/Chrome standalone app mode with zero browser tabs and no URL bar).
   * **Dynamic Port Failover:** If port 9090 is in use, CyFence dynamically binds the next available port (9091, 9092, etc.).
   * **Single-Instance Management:** Launching `cyfence.exe` a second time brings the existing desktop window into focus instead of creating duplicate background processes.
   * **Clean Exit:** Click the **✕ Exit Application** button in the top navigation bar to stop the local engine and close the app cleanly.

---

## 🖥️ Complete Application Feature Tour (In the Web GUI)

Every capability of the security engine is accessible directly through the visual tabs:

### 1. 🚀 Single Target Audit & Deep Red Team VAPT
* **Scan Profile Selector**:
  * 🔴 **Deep Red Team VAPT (Full Injections)** *(Default)*: Active recursive spidering, SQL Injection fuzzing across 15+ database signatures (MySQL, PostgreSQL, SQLite, MSSQL, Oracle), Reflected XSS probing, Local File Inclusion (LFI / Path Traversal), Cloud Metadata SSRF (`169.254.169.254`), Open Redirects, and GraphQL Introspection.
  * 🛡️ **Standard ASVS Audit**: Full OWASP ASVS v4.0 baseline across 50+ sensitive metadata paths (`.env`, `.git/config`, `actuator/heapdump`, `backup.sql`, `docker-compose.yml`), CORS policies, and RFC 8725 JWT compliance.
  * ⚡ **Quick Recon**: Rapid perimeter verification, TLS cipher suites, and security headers.
* **Interactive Multi-Stage Progress Stepper**:
  * Real-time 5-phase visual stepper: `① Recon & TLS` $\rightarrow$ `② Endpoint Spider` $\rightarrow$ `③ Active Injections` $\rightarrow$ `④ API & GraphQL` $\rightarrow$ `⑤ Posture Grading`.
* **Live Cyber Streaming Console**:
  * Real-time dark-mode terminal streaming every probe, injected payload, and parameter evaluation via Server-Sent Events.
* **Exploit Proof-of-Concept (PoC) Drawers**:
  * Every confirmed injection finding includes a detailed **PoC Box** containing the vulnerable parameter, injected payload, database engine detected, raw response snippet evidence, and reproducible URL.
* **Instant Report Exports**:
  * Export visual **HTML Reports**, machine-readable **JSON**, or GitHub-flavored **Markdown** with 1 click.

### 2. 🔌 Custom API & Network Engine
* **Host Network Adapter Inspector**:
  * Inspects your machine's network interfaces and surfaces your real host network IP (e.g. `192.168.x.x` or `10.x.x.x`) alongside the secure loopback (`127.0.0.1`), with 1-click IP copy buttons.
* **Custom REST API & OpenAPI Tester**:
  * Ingest any **OpenAPI 3.0 / Swagger specification** via live URL or paste raw JSON/YAML.
  * Automatically extracts endpoints, HTTP methods, and parameter definitions ready for penetration fuzzing.
* **Bring Your Own AI API (BYOK)**:
  * Configure your own **OpenAI**, **Anthropic Claude**, **Google Gemini**, or **Ollama** API keys, custom models, and endpoints.
  * Test AI connectivity live with the built-in diagnostic test button.

### 3. 📋 Multi-Target Fleet Batch Auditing
* **No text files needed**: Paste multiple URLs directly into the browser text area (or click **Load Sample Targets**).
* Click **Launch Fleet Batch Audit**.
* Watch the **real-time progress bar** and view the **Fleet Summary Matrix** comparing scores, grades (A–F), and defect counts across your infrastructure.
* Click **Inspect** on any target row to immediately view its detailed findings.

### 4. ⚖️ Configuration Drift & Regression (Diff Engine)
* Paste baseline and current audit results into side-by-side text boxes (or click **Load Sample Baseline & Current**).
* Click **Compare Audits**.
* Instantly view the **Score Delta Badge** (e.g., `+30 Points (IMPROVED)` or `-15 Points (DEGRADED)`).
* Inspect the **New Vulnerabilities** list to catch regressions and the **Resolved Vulnerabilities** list to verify fixes.

### 5. 🛡️ Blue Team Auto-Remediation & SIEM Exporter
* Automatically generates tailored configuration snippets based on audit findings:
  * **Nginx**: Ready-to-paste reverse proxy security headers and dotfile block rules.
  * **Apache**: `.htaccess` / `httpd.conf` defensive directives.
  * **Caddy**: Hardened Caddyfile configuration.
  * **Sigma Rule (YAML)**: Pre-configured SIEM detection rules.
  * **Elasticsearch Query DSL**: Ready-to-use search query for SOC alerting.
* Click **📋 Copy** to copy configurations to clipboard, or click **💾 Download** to save `.conf` / `.yml` files to disk.

### 6. 🤖 AI Security Advisor (Human Approval Mandatory)
* Choose your preferred AI engine:
  * **Ollama (100% Offline / Local Air-Gapped Llama 3)**
  * **Anthropic Claude (claude-3-5-sonnet)**
  * **OpenAI (gpt-4o-mini)**
* Click **Synthesize AI Remediation Advisory**.
* **Strict Human-in-the-Loop Workflow**: Review the AI proposal and click **✓ Approve for Staging** or **✕ Reject Proposal**. All approvals are logged to an audit trail with timestamps.

### 7. 📖 Architecture & Product Tour
* Interactive guide displaying OWASP ASVS v4.0 mapping, ATT&CK/D3FEND technique alignment, 50,000 node benchmark metrics, and the 8/8 VAPT security verification checklist.

---

## ⚡ 50,000 Node Enterprise Scale Performance

ClassiGuard CyFence includes a built-in stress-tested audit engine verified against 50,000 synthetic enterprise machines:

* **Total Nodes Audited**: 50,000 machines
* **Execution Time**: **~0.36 seconds** (359.50 ms)
* **Throughput**: **~139,000 machines / second**
* **Memory Stability**: Peak heap of **8.27 MB** (+2.55 MB delta, zero memory leaks, clean V8 garbage collection)
* **Fleet Posture Profile**:
  * Grade A (Hardened Baseline): 10,000 (20.0%)
  * Grade B (Minor Gaps): 10,000 (20.0%)
  * Grade C (Moderate Risk): 10,000 (20.0%)
  * Grade D (High Risk): 10,000 (20.0%)
  * Grade F (Critical Defects): 10,000 (20.0%)

---

## 📁 Executable Artifact

* **`dist/cyfence.exe`**: Pre-compiled single standalone Windows executable (~89.8 MB). Simply double-click to launch!

---

## 🔌 Optional CI/CD Automation (Headless CLI Mode)

For automated DevOps pipelines, Jenkins, and GitHub Actions where no graphical browser is present, passing arguments directly to `cyfence.exe` executes in headless CLI mode:

```bash
# Automated CI/CD quality gate (exits with code 1 if score is below 80)
cyfence.exe https://staging.example.corp --min-score 80 --json report.json

# Headless multi-target audit from file
cyfence.exe --targets targets.txt --html batch-report.html
```

*(If executed without arguments, CyFence automatically launches the Desktop Application).*

---

## 🛡️ Responsible Disclosure & Security

If you identify a security defect in ClassiGuard CyFence, please review our **[Security Policy](SECURITY.md)** and submit a private report via GitHub Advisories.

---

## 📜 License

Licensed under the **[ClassiGuard Community Evaluation License (6-Month Term)](LICENSE)**. All use is subject to the **[Legal Disclaimer](DISCLAIMER.md)**.
