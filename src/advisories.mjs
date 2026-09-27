// Published security advisories for Claude Code (npm @anthropic-ai/claude-code), from the GitHub
// Advisory Database on the date below. A snapshot shipped with the package: blackbrake never
// fetches it at run time. Refreshed with each release.
export const ADVISORIES_DATE = '2026-09-26';

export const ADVISORIES = [
  { id: "CVE-2026-55607", severity: "high", fixed: "2.1.163", summary: "Sandbox Escape via Git Worktree Path Confusion Allows Unsandboxed Code Execution" },
  { id: "CVE-2026-46406", severity: "medium", fixed: "2.1.128", summary: "an Insecure Temporary File in /copy Command that Enables Response Disclosure and Symlink-Based File Write" },
  { id: "CVE-2026-54316", severity: "medium", fixed: "2.1.163", summary: "Out-of-Band Data Exfiltration via Pre-Approved HuggingFace Domain in WebFetch" },
  { id: "CVE-2026-40068", severity: "high", fixed: "2.1.84", summary: "Trust Dialog Bypass via Git Worktree Spoofing Allows Arbitrary Code Execution" },
  { id: "CVE-2026-39861", severity: "high", fixed: "2.1.64", summary: "Sandbox Escape via Symlink Following Allows Arbitrary File Write Outside Workspace" },
  { id: "CVE-2026-35603", severity: "medium", fixed: "2.1.75", summary: "Insecure System-Wide Configuration Loading Enables Local Privilege Escalation on Windows" },
  { id: "CVE-2026-33068", severity: "high", fixed: "2.1.53", summary: "a Workspace Trust Dialog Bypass via Repo-Controlled Settings File" },
  { id: "CVE-2026-25725", severity: "high", fixed: "2.1.2", summary: "Sandbox Escape via Persistent Configuration Injection in settings.json" },
  { id: "CVE-2026-25724", severity: "low", fixed: "2.1.7", summary: "Permission Deny Bypass Through Symbolic Links" },
  { id: "CVE-2026-25723", severity: "high", fixed: "2.0.55", summary: "Vulnerable to Command Injection via Piped sed Command Bypasses File Write Restrictions" },
  { id: "CVE-2026-25722", severity: "high", fixed: "2.0.57", summary: "Vulnerable to Command Injection via Directory Change Bypasses Write Protection" },
  { id: "CVE-2026-24887", severity: "high", fixed: "2.0.72", summary: "a Command Injection in find Command Bypasses User Approval Prompt" },
  { id: "CVE-2026-24053", severity: "high", fixed: "2.0.74", summary: "a Path Restriction Bypass via ZSH Clobber which Allows Arbitrary File Writes" },
  { id: "CVE-2026-24052", severity: "high", fixed: "1.0.111", summary: "a Domain Validation Bypass which Allows Automatic Requests to Attacker-Controlled Domains" },
  { id: "CVE-2026-21852", severity: "medium", fixed: "2.0.65", summary: "Leaks Data via Malicious Environment Configuration Before Trust Confirmation" },
  { id: "CVE-2025-66032", severity: "high", fixed: "1.0.93", summary: "Command Validation Bypass Allows Arbitrary Code Execution" },
  { id: "CVE-2025-64755", severity: "high", fixed: "2.0.31", summary: "Sed Command Validation Bypass that Allows Arbitrary File Writes" },
  { id: "CVE-2025-65099", severity: "high", fixed: "1.0.39", summary: "vulnerable to command execution prior to startup trust dialog" },
  { id: "CVE-2025-59829", severity: "low", fixed: "1.0.120", summary: "permission deny bypass through symlink" },
  { id: "CVE-2025-59536", severity: "high", fixed: "1.0.111", summary: "can execute commands prior to the startup trust dialog" },
  { id: "CVE-2025-59828", severity: "high", fixed: "1.0.39", summary: "Vulnerable to Arbitrary Code Execution via Plugin Autoloading with Specific Yarn Versions" },
  { id: "CVE-2025-59041", severity: "high", fixed: "1.0.105", summary: "vulnerable to arbitrary code execution caused by maliciously configured git email" },
  { id: "CVE-2025-58764", severity: "high", fixed: "1.0.105", summary: "rg vulnerability does not protect against approval prompt bypass" },
  { id: "GHSA-ph6w-f82w-28w6", severity: "high", fixed: "1.0.87", summary: "Vulnerable to Arbitrary Code Execution Due to Insufficient Startup Warning" },
  { id: "CVE-2025-55284", severity: "high", fixed: "1.0.4", summary: "Claude Code's Permissive Default Allowlist Enables Unauthorized File Read and Network Exfiltration in Claude Code" },
  { id: "CVE-2025-54795", severity: "high", fixed: "1.0.20", summary: "echo command allowed bypass of user approval prompt for command execution" },
  { id: "CVE-2025-54794", severity: "high", fixed: "0.2.111", summary: "Research Preview has a Path Restriction Bypass which could allow unauthorized file access" },
  { id: "CVE-2025-52882", severity: "high", fixed: "1.0.24", summary: "Improper Authorization via websocket connections from arbitrary origins" },
];

const parts = (v) => String(v).split(/[.-]/).map((n) => Number.parseInt(n, 10) || 0);

export function olderThan(a, b) {
  const x = parts(a);
  const y = parts(b);

  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0);

  return false;
}

// Advisories fixed in a later version than the one in use.
export const openAdvisories = (version) => (version ? ADVISORIES.filter((a) => olderThan(version, a.fixed)) : []);
