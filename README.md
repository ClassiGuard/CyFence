# 🛡️ ClassiGuard CyFence

> **Enterprise Defensive Web Security Posture & Compliance Suite**  
> *Single Standalone Executable • One-Click Web GUI • Zero External Dependencies • Offline & Air-Gapped Ready • AI-Assisted with Mandatory Human Approval*

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

## 🌟 How to Run ClassiGuard CyFence (One-Click Launch)

ClassiGuard CyFence is packaged as a **single, self-contained standalone executable**. You do **not** need to install Node.js, configure dependencies, or run terminal commands.

### 🚀 Execution Method

```
               ┌────────────────────────────────────────────────────────┐
               │                  DOWNLOAD & DOUBLE-CLICK               │
               │                    dist/cyfence.exe                    │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │           AUTOMATIC WEB GUI INITIALIZATION             │
               │  • Background server starts on http://127.0.0.1:9090   │
               │  • System default web browser launches automatically   │
               │  • Ephemeral CSRF guard and loopback isolation active  │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │            COMPLETE DEFENSIVE SECURITY SUITE           │
               │       All features accessible via point-and-click!     │
               └────────────────────────────────────────────────────────┘
```

1. **Download the Executable**:
   * Windows: Download **[`dist/cyfence.exe`](dist/cyfence.exe)**
   * Linux: Download **[`dist/classiguard-cyfence-linux.tar.gz`](dist/classiguard-cyfence-linux.tar.gz)**
2. **Launch the Application**:
   * **Windows:** Simply **double-click `cyfence.exe`** (or run `.\cyfence.exe` in terminal).
   * **Linux:** Extract the archive and execute `./cyfence`.
3. **Use the Application**:
   * CyFence immediately starts its embedded, air-gapped server on `http://127.0.0.1:9090` and **automatically opens your web browser**.
   * All options and operations are performed visually through the Web GUI.

---

## 🖥️ Complete Application Feature Tour (In the Web GUI)

Every capability of the engine is accessible directly through the visual tabs:

### 1. 🚀 Single Target Security Audit
* **Enter Target URL**: Type or paste any endpoint (e.g. `https://example.com` or local intranet).
* **Point-and-Click Controls**:
  * Toggle sensitive route checks (`/.git`, `/.env`, Spring Boot Actuator).
  * Check for JWT RFC 8725 compliance by pasting tokens.
  * Send custom audit headers via a simple input box.
* **Instant Export Buttons**:
  * Click **Export HTML** to download a visual, styled report.
  * Click **Export JSON** for machine-readable raw data.
  * Click **Export MD** for GitHub-flavored Markdown summaries.
* **Filter Findings**: Click badges to filter between **Critical**, **High**, **Medium**, **Low**, and **Passed** controls.

### 2. 📋 Multi-Target Fleet Batch Auditing
* **No text files needed**: Paste multiple URLs directly into the browser text area (or click **Load Sample Targets**).
* Click **Launch Fleet Batch Audit**.
* Watch the **real-time progress bar** and view the **Fleet Summary Matrix** comparing scores, grades (A–F), and defect counts.
* Click **Inspect** on any target row to immediately view its detailed findings.

### 3. ⚖️ Configuration Drift & Regression (Diff Engine)
* Paste baseline and current audit results into side-by-side text boxes (or click **Load Sample Baseline & Current**).
* Click **Compare Audits**.
* Instantly view the **Score Delta Badge** (e.g., `+30 Points (IMPROVED)` or `-15 Points (DEGRADED)`).
* Inspect the **New Vulnerabilities** list to catch regressions and the **Resolved Vulnerabilities** list to verify fixes.

### 4. 🛡️ Blue Team Auto-Remediation & SIEM Exporter
* Automatically generates tailored configuration snippets based on audit findings:
  * **Nginx**: Ready-to-paste reverse proxy security headers and dotfile block rules.
  * **Apache**: `.htaccess` / `httpd.conf` defensive directives.
  * **Caddy**: Hardened Caddyfile configuration.
  * **Sigma Rule (YAML)**: Pre-configured SIEM detection rules.
  * **Elasticsearch Query DSL**: Ready-to-use search query for SOC alerting.
* Click **📋 Copy** to copy configurations to clipboard, or click **💾 Download** to save `.conf` / `.yml` files to disk.

### 5. 🤖 AI Security Advisor (Human Approval Mandatory)
* Choose your preferred AI engine:
  * **Ollama (100% Offline / Local Air-Gapped Llama 3)**
  * **Anthropic Claude (claude-3-5-sonnet)**
  * **OpenAI (gpt-4o-mini)**
* Click **Synthesize AI Remediation Advisory**.
* **Strict Human-in-the-Loop Workflow**: Review the AI proposal and click **✓ Approve for Staging** or **✕ Reject Proposal**. All approvals are logged to an audit trail with timestamps.

### 6. 📖 Interactive Architecture Tour & Reference
* Integrated guide displaying OWASP ASVS v4.0 mapping, ATT&CK/D3FEND technique alignment, 50,000 node benchmark metrics, and the 8/8 VAPT security verification checklist.

---

## ⚡ 50,000 Node Enterprise Scale Performance

ClassiGuard CyFence includes a built-in stress-tested audit engine verified against 50,000 synthetic enterprise machines:

* **Total Nodes Audited**: 50,000 machines
* **Execution Time**: **~0.33 seconds** (334.76 ms)
* **Throughput**: **~149,300 machines / second**
* **Memory Stability**: Peak heap of **9.95 MB** (+4.23 MB delta, zero memory leaks, clean V8 garbage collection)
* **Fleet Posture Profile**:
  * Grade A (Hardened Baseline): 10,000 (20.0%)
  * Grade B (Minor Gaps): 10,000 (20.0%)
  * Grade C (Moderate Risk): 10,000 (20.0%)
  * Grade D (High Risk): 10,000 (20.0%)
  * Grade F (Critical Defects): 10,000 (20.0%)

---

## 📁 Standalone Packages Available in `dist/`

* **`dist/cyfence.exe`**: Pre-compiled standalone Windows executable (~89.8 MB). Simply double-click to run!
* **`dist/classiguard-cyfence.exe`**: Full-name standalone Windows executable.
* **`dist/classiguard-cyfence-linux.tar.gz`**: Standalone Linux distribution archive (~38 KB).
* **`dist/bundle.cjs`**: Universal single-file distribution (~135 KB).

---

## 🔌 Optional CI/CD Automation (Headless Mode)

For automated DevOps pipelines, Jenkins, and GitHub Actions where no graphical browser is present, passing arguments directly to `cyfence.exe` executes in headless mode:

```bash
# Automated CI/CD quality gate (exits with code 1 if score is below 80)
cyfence.exe https://staging.example.corp --min-score 80 --json report.json

# Headless multi-target audit from file
cyfence.exe --targets targets.txt --html batch-report.html
```

*(If no arguments are provided, CyFence automatically launches the Web GUI suite).*

---

## 🛡️ Responsible Disclosure & Security

If you identify a security defect in ClassiGuard CyFence, please review our **[Security Policy](SECURITY.md)** and submit a private report via GitHub Advisories.

---

## 📜 License

Licensed under the **[ClassiGuard Community Evaluation License (6-Month Term)](LICENSE)**. All use is subject to the **[Legal Disclaimer](DISCLAIMER.md)**.
