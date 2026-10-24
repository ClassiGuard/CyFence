# Security Policy for ClassiGuard CyFence

## 1. Supported Releases

| Version | Evaluation Period | Security Updates |
| :--- | :--- | :--- |
| **v1.0.0 (Community Evaluation)** | **October 2026 – April 2027** | ✅ Active Critical Patches |
| Legacy Builds | N/A | ❌ End of Life |

---

## 2. Reporting a Security Vulnerability

If you identify a security vulnerability, weakness, or flaw within **ClassiGuard CyFence** (e.g. in the standalone binary, the HTTP probe engine, or the embedded Web GUI):

1. **Do NOT open a public GitHub issue.**
2. Report the vulnerability privately via **GitHub Security Advisories** on the repository:
   `https://github.com/ClassiGuard/CyFence/security/advisories/new`
   or via email to `security@classiguard.com`.
3. Please provide:
   * A detailed description of the vulnerability (CWE, potential impact).
   * Reproduction steps or a minimal test case.
   * Suggested remediation or defensive patch (if known).

---

## 3. Vulnerability Response Timeline

* **Initial Acknowledgment:** Within 48 hours.
* **Assessment & Severity Triaging:** Within 5 business days.
* **Remediation & Patch Deployment:** Critical vulnerabilities are addressed via expedited binary releases within 14 business days.

---

## 4. Operator Security Guidelines

When running ClassiGuard CyFence in enterprise environments:
* **Loopback Binding:** The Web GUI binds strictly to `127.0.0.1` by default. Do not expose port `9090` to untrusted LANs or public internet interfaces.
* **Air-Gapped Operation:** The tool runs 100% offline with zero outbound network calls other than to the specific target URL provided by the operator.
* **Report Protection:** Stored audit reports and JSON artifacts contain infrastructure configuration data; protect them with appropriate filesystem access control permissions.
