"""
Startup hardening and baseline threat assessment.

Runs a local security posture review when protection starts, with additional
focus on Windows malware persistence, firewall posture, and vulnerable native
services commonly abused by malware.
"""

import json
import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

import logging

logger = logging.getLogger("StartupHardening")


class StartupThreatMonitor:
    """Run startup-time security checks and apply safe defensive actions."""

    KNOWN_MALWARE_KEYWORDS = {
        "mimikatz",
        "meterpreter",
        "cobalt",
        "beacon",
        "sliver",
        "empire",
        "quasar",
        "njrat",
        "remcos",
        "trickbot",
        "emotet",
        "cryptolocker",
        "wannacry",
        "ransom",
        "stealer",
        "keylogger",
        "backdoor",
        "loader",
        "dropper",
    }
    LOLBIN_KEYWORDS = {
        "powershell",
        "pwsh",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "wmic",
        "msbuild",
    }
    WINDOWS_SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd"}
    EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".pif", ".com"}
    DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}
    HIGH_RISK_WINDOWS_PORTS = [135, 137, 138, 139, 445, 3389, 5985, 5986]
    REPORT_PATH = Path.home() / ".sentinelai_startup_assessment.json"

    def __init__(self, prevention_system, defense_coordinator=None, callback: Optional[Callable] = None):
        self.prevention_system = prevention_system
        self.defense_coordinator = defense_coordinator
        self.callback = callback

    def run_startup_assessment(self, apply_firewall_hardening: bool = True) -> Dict:
        """Run a startup baseline assessment and remediate obvious threats."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "host": {
                "hostname": platform.node(),
                "platform": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
            },
            "findings": {
                "processes": self._scan_running_processes(),
                "files": self._scan_startup_files(),
                "vulnerabilities": self._assess_platform_security(),
                "firewall": self._assess_firewall_posture(),
            },
            "actions": [],
            "summary": {},
        }

        report["actions"].extend(self._remediate_findings(report["findings"]))

        if apply_firewall_hardening:
            hardening = self.prevention_system.harden_firewall(
                profile="startup",
                high_risk_ports=self.HIGH_RISK_WINDOWS_PORTS,
            )
            report["actions"].append(
                {
                    "type": "firewall_hardening",
                    "status": "completed" if hardening.get("success") else "partial",
                    "details": hardening,
                }
            )

        total_findings = sum(len(items) for items in report["findings"].values())
        critical_findings = sum(
            1
            for group in report["findings"].values()
            for item in group
            if item.get("severity") == "CRITICAL"
        )
        high_findings = sum(
            1
            for group in report["findings"].values()
            for item in group
            if item.get("severity") == "HIGH"
        )
        report["summary"] = {
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "actions_taken": len(report["actions"]),
        }

        self._persist_report(report)

        self._emit(
            {
                "event": "STARTUP_ASSESSMENT_COMPLETED",
                "report": report,
            }
        )
        return report

    def _scan_running_processes(self) -> List[Dict]:
        """Identify suspicious running processes, including Windows LOLBin abuse."""
        try:
            import psutil
        except ImportError:
            logger.warning("psutil is not available; skipping process scan")
            return []

        findings: List[Dict] = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").strip()
                exe = proc.info.get("exe") or ""
                cmdline = " ".join(proc.info.get("cmdline") or [])
                haystack = f"{name} {exe} {cmdline}".lower()
                score = 0
                reasons = []

                matched_malware = [kw for kw in self.KNOWN_MALWARE_KEYWORDS if kw in haystack]
                if matched_malware:
                    score += 80
                    reasons.append(f"Known malware keyword(s): {', '.join(sorted(matched_malware))}")

                matched_lolbins = [kw for kw in self.LOLBIN_KEYWORDS if kw in haystack]
                if matched_lolbins:
                    score += 20
                    reasons.append(f"LOLBIN execution chain: {', '.join(sorted(matched_lolbins))}")

                suspicious_tokens = [
                    " -enc ",
                    "frombase64string",
                    "downloadstring",
                    "invoke-expression",
                    " iwr ",
                    " http://",
                    " https://",
                    "\\appdata\\local\\temp",
                    "/tmp/",
                    "/var/tmp/",
                ]
                matched_tokens = [token.strip() for token in suspicious_tokens if token in haystack]
                if matched_tokens:
                    score += 30
                    reasons.append(f"Suspicious command indicators: {', '.join(matched_tokens)}")

                if score < 50:
                    continue

                findings.append(
                    {
                        "category": "process",
                        "severity": self._severity_from_score(score),
                        "score": score,
                        "name": name or "unknown",
                        "pid": proc.info.get("pid"),
                        "path": exe,
                        "description": "; ".join(reasons),
                    }
                )
            except Exception:
                continue

        return findings

    def _scan_startup_files(self) -> List[Dict]:
        """Inspect common startup and persistence locations for risky files."""
        findings: List[Dict] = []
        for base_dir in self._candidate_startup_paths():
            if not base_dir.exists():
                continue

            try:
                candidates = [base_dir] if base_dir.is_file() else list(base_dir.rglob("*"))
            except Exception:
                continue

            for entry in candidates:
                if not entry.is_file():
                    continue

                score, reasons = self._score_startup_file(entry)
                if score < 50:
                    continue

                findings.append(
                    {
                        "category": "file",
                        "severity": self._severity_from_score(score),
                        "score": score,
                        "path": str(entry),
                        "description": "; ".join(reasons),
                    }
                )

        return findings

    def _candidate_startup_paths(self) -> List[Path]:
        """Return startup/persistence paths for the current platform."""
        system = platform.system()
        home = Path.home()

        if system == "Windows":
            raw_paths = [
                os.getenv("APPDATA", ""),
                os.getenv("PROGRAMDATA", ""),
                os.getenv("TEMP", ""),
                r"C:\Users\Public",
                r"C:\ProgramData",
                r"C:\Windows\Temp",
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            ]
            normalized = []
            for raw in raw_paths:
                if not raw:
                    continue
                base = Path(raw)
                if raw.endswith("Roaming"):
                    normalized.append(base / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
                else:
                    normalized.append(base)
            return normalized

        return [
            home / ".config" / "autostart",
            Path("/etc/xdg/autostart"),
            Path("/tmp"),
            Path("/var/tmp"),
        ]

    def _score_startup_file(self, entry: Path) -> tuple[int, List[str]]:
        """Score suspicious persistence files."""
        score = 0
        reasons: List[str] = []
        name = entry.name.lower()
        suffixes = [suffix.lower() for suffix in entry.suffixes]
        final_suffix = suffixes[-1] if suffixes else ""

        if final_suffix in self.WINDOWS_SCRIPT_EXTENSIONS:
            score += 35
            reasons.append(f"Script file in startup/persistence path ({final_suffix})")

        if final_suffix in self.EXECUTABLE_EXTENSIONS:
            score += 25
            reasons.append(f"Executable file in startup/persistence path ({final_suffix})")

        if len(suffixes) >= 2 and suffixes[-2] in self.DOCUMENT_EXTENSIONS and suffixes[-1] in self.EXECUTABLE_EXTENSIONS:
            score += 40
            reasons.append("Double-extension masquerading as document")

        matched_keywords = [kw for kw in self.KNOWN_MALWARE_KEYWORDS if kw in name]
        if matched_keywords:
            score += 70
            reasons.append(f"Malware-themed filename: {', '.join(sorted(matched_keywords))}")

        if name.startswith("."):
            score += 10
            reasons.append("Hidden file in persistence path")

        return score, reasons

    def _assess_platform_security(self) -> List[Dict]:
        """Assess OS-specific security posture."""
        system = platform.system()
        if system == "Windows":
            return self._assess_windows_security()
        if system == "Linux":
            return self._assess_linux_security()
        return []

    def _assess_windows_security(self) -> List[Dict]:
        """Assess common Windows malware exposure areas."""
        payload = self._run_powershell_json(
            r"""
            $profiles = @()
            try {
                $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled
            } catch {}
            $defender = $null
            try {
                $defender = Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableScriptScanning, DisableIOAVProtection
            } catch {}
            $smb1 = $null
            try {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
                $smb1 = $feature.State
            } catch {}
            $rdp = $null
            try {
                $rdp = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
            } catch {}
            [pscustomobject]@{
                firewallProfiles = $profiles
                defender = $defender
                smb1 = $smb1
                rdpDisabled = $rdp
            } | ConvertTo-Json -Depth 4
            """
        )

        if not payload:
            return []

        findings: List[Dict] = []
        for profile_info in payload.get("firewallProfiles") or []:
            if not profile_info.get("Enabled", True):
                findings.append(
                    {
                        "category": "windows_vulnerability",
                        "severity": "HIGH",
                        "score": 75,
                        "description": f"Windows Firewall profile disabled: {profile_info.get('Name', 'Unknown')}",
                    }
                )

        defender = payload.get("defender") or {}
        if defender.get("DisableRealtimeMonitoring"):
            findings.append(
                {
                    "category": "windows_vulnerability",
                    "severity": "CRITICAL",
                    "score": 90,
                    "description": "Microsoft Defender real-time monitoring is disabled",
                }
            )
        if defender.get("DisableScriptScanning"):
            findings.append(
                {
                    "category": "windows_vulnerability",
                    "severity": "HIGH",
                    "score": 70,
                    "description": "Microsoft Defender script scanning is disabled",
                }
            )
        if str(payload.get("smb1", "")).lower() == "enabled":
            findings.append(
                {
                    "category": "windows_vulnerability",
                    "severity": "CRITICAL",
                    "score": 95,
                    "description": "Legacy SMBv1 is enabled, increasing ransomware/lateral-movement risk",
                }
            )
        if payload.get("rdpDisabled") == 0:
            findings.append(
                {
                    "category": "windows_vulnerability",
                    "severity": "MEDIUM",
                    "score": 55,
                    "description": "Remote Desktop is enabled; verify MFA and source restrictions",
                }
            )

        return findings

    def _assess_linux_security(self) -> List[Dict]:
        """Assess generic Linux hardening posture relevant to malware containment."""
        findings: List[Dict] = []
        if shutil.which("ufw"):
            status = self._run_command(["ufw", "status"], timeout=8)
            if status and "status: inactive" in status.lower():
                findings.append(
                    {
                        "category": "linux_vulnerability",
                        "severity": "MEDIUM",
                        "score": 55,
                        "description": "UFW is installed but inactive",
                    }
                )

        if Path("/etc/ssh/sshd_config").exists():
            try:
                sshd_config = Path("/etc/ssh/sshd_config").read_text(encoding="utf-8", errors="ignore").lower()
                if "permitrootlogin yes" in sshd_config:
                    findings.append(
                        {
                            "category": "linux_vulnerability",
                            "severity": "MEDIUM",
                            "score": 50,
                            "description": "SSH root login appears enabled",
                        }
                    )
            except Exception:
                pass

        return findings

    def _assess_firewall_posture(self) -> List[Dict]:
        """Assess current firewall state before hardening is applied."""
        system = platform.system()
        findings: List[Dict] = []

        if system == "Windows":
            payload = self._run_powershell_json(
                "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Depth 3"
            )
            if isinstance(payload, dict):
                payload = [payload]
            for profile_info in payload or []:
                if not profile_info.get("Enabled", True):
                    findings.append(
                        {
                            "category": "firewall",
                            "severity": "HIGH",
                            "score": 70,
                            "description": f"Firewall profile disabled: {profile_info.get('Name', 'Unknown')}",
                        }
                    )
            return findings

        if shutil.which("ufw"):
            status = self._run_command(["ufw", "status"], timeout=8)
            if status and "status: inactive" in status.lower():
                findings.append(
                    {
                        "category": "firewall",
                        "severity": "MEDIUM",
                        "score": 55,
                        "description": "Host firewall is inactive (ufw)",
                    }
                )
            return findings

        if shutil.which("iptables"):
            rules = self._run_command(["iptables", "-S"], timeout=8)
            if rules and "-P INPUT ACCEPT" in rules and "SENTINELAI" not in rules:
                findings.append(
                    {
                        "category": "firewall",
                        "severity": "MEDIUM",
                        "score": 45,
                        "description": "iptables default INPUT policy is ACCEPT without SentinelAI hardening rules",
                    }
                )

        return findings

    def _run_powershell_json(self, script: str) -> Optional[Dict]:
        """Run PowerShell and parse JSON output when available."""
        if platform.system() != "Windows":
            return None

        output = self._run_command(["powershell", "-NoProfile", "-Command", script], timeout=20)
        if not output:
            return None

        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.debug("PowerShell JSON parsing failed")
            return None

    def _run_command(self, command: List[str], timeout: int = 10) -> str:
        """Run a command and return stdout without raising."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return (result.stdout or result.stderr or "").strip()
        except Exception:
            return ""

    def _remediate_findings(self, findings: Dict[str, List[Dict]]) -> List[Dict]:
        """Apply minimal automatic remediation for clearly malicious items."""
        actions: List[Dict] = []

        for finding in findings.get("files", []):
            if finding.get("severity") not in {"HIGH", "CRITICAL"}:
                continue
            file_path = finding.get("path")
            if not file_path:
                continue
            self.prevention_system.block_file(file_path, reason=f"Startup persistence threat: {finding.get('description')}")
            actions.append(
                {
                    "type": "quarantine_file",
                    "target": file_path,
                    "status": "executed",
                }
            )

        for finding in findings.get("processes", []):
            if finding.get("severity") != "CRITICAL":
                continue
            process_name = finding.get("name")
            if not process_name:
                continue
            self.prevention_system.block_application(process_name, reason=f"Critical startup process threat: {finding.get('description')}")
            actions.append(
                {
                    "type": "block_application",
                    "target": process_name,
                    "status": "executed",
                }
            )

        for finding in findings.get("vulnerabilities", []):
            if finding.get("severity") in {"HIGH", "CRITICAL"}:
                actions.append(
                    {
                        "type": "security_posture_alert",
                        "target": finding.get("category", "platform"),
                        "status": "reported",
                        "details": finding,
                    }
                )

        return actions

    def _severity_from_score(self, score: int) -> str:
        """Convert score to severity."""
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 45:
            return "MEDIUM"
        return "LOW"

    def _emit(self, event: Dict) -> None:
        """Emit callback events without breaking protection startup."""
        if not self.callback:
            return

        try:
            self.callback(event)
        except Exception as exc:
            logger.debug(f"Startup hardening callback failed: {exc}")

    def _persist_report(self, report: Dict) -> None:
        """Persist the latest startup assessment for later inspection."""
        try:
            self.REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error(f"Failed to persist startup assessment report: {exc}")

    @classmethod
    def get_latest_report(cls) -> Dict:
        """Return the most recent startup assessment report, if present."""
        try:
            if cls.REPORT_PATH.exists():
                return json.loads(cls.REPORT_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error(f"Failed to load startup assessment report: {exc}")
        return {}