#!/usr/bin/env python3
"""workflow-audit-cli: Enhanced CLI for Workflow Security Auditing"""

import os, re, json, argparse
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Set
from enum import Enum
from datetime import datetime
import sys

class Severity(Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"; LOW = "LOW"; INFO = "INFO"

class Category(Enum):
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    UNSAFE_CODE_EXECUTION = "unsafe_code_execution"
    DATA_LEAKAGE = "data_leakage"
    COMPLIANCE_VIOLATION = "compliance_violation"
    INSECURE_CONFIG = "insecure_config"
    SECRET_EXPOSURE = "secret_exposure"

@dataclass
class Finding:
    rule_id: str; severity: Severity; category: Category; title: str
    description: str; file_path: str; recommendation: str = ""

class AuditReport:
    def __init__(self):
        self.scan_time = ""
        self.files_scanned = 0
        self.findings: List[Finding] = []
        self.suppressed_rules: Set[str] = set()
    
    @property
    def total(self) -> int: return len(self.findings)
    
    @property
    def by_severity(self) -> Dict[str, int]:
        r = {}
        for f in self.findings:
            s = f.severity.value
            r[s] = r.get(s, 0) + 1
        return r

RULES = {
    "PERM001": (r'permissions:.*\s+contents:\s+write', Severity.HIGH, Category.EXCESSIVE_PERMISSIONS, "Overly Permissive Token"),
    "PERM002": (r'permissions:.*\s+contents:\s+admin', Severity.CRITICAL, Category.EXCESSIVE_PERMISSIONS, "Admin Permissions"),
    "PERM003": (r'permissions:.*\s+secrets:\s+write', Severity.CRITICAL, Category.EXCESSIVE_PERMISSIONS, "Secrets Write"),
    "PERM004": (r'pull_request_target', Severity.CRITICAL, Category.EXCESSIVE_PERMISSIONS, "pull_request_target"),
    "EXEC001": (r'rm\s+-rf\s+/', Severity.CRITICAL, Category.UNSAFE_CODE_EXECUTION, "Recursive Delete"),
    "EXEC002": (r'eval\s+\$', Severity.CRITICAL, Category.UNSAFE_CODE_EXECUTION, "Eval Command"),
    "EXEC007": (r'curl\s+.*\|\s*(sh|bash)', Severity.CRITICAL, Category.UNSAFE_CODE_EXECUTION, "Curl-Pipe-Sh"),
    "EXEC008": (r'wget\s+.*\|\s*(sh|bash)', Severity.CRITICAL, Category.UNSAFE_CODE_EXECUTION, "Wget-Pipe-Sh"),
    "EXEC009": (r'docker\s+run\s+--privileged', Severity.CRITICAL, Category.UNSAFE_CODE_EXECUTION, "Privileged Docker"),
    "SECR001": (r'ghp_[A-Za-z0-9]{36}', Severity.CRITICAL, Category.SECRET_EXPOSURE, "GitHub PAT"),
    "SECR002": (r'AKIA[0-9A-Z]{16}', Severity.CRITICAL, Category.SECRET_EXPOSURE, "AWS Key"),
    "SECR003": (r'sk-[A-Za-z0-9]{48,}', Severity.CRITICAL, Category.SECRET_EXPOSURE, "OpenAI Key"),
    "SECR006": (r'xox[baprs]-[A-Za-z0-9\-_]+', Severity.CRITICAL, Category.SECRET_EXPOSURE, "Slack Token"),
    "DATA001": (r'echo\s+.*\$\{\{.*secrets', Severity.HIGH, Category.DATA_LEAKAGE, "Secret Logging"),
    "DATA002": (r'http://(?!localhost)', Severity.HIGH, Category.DATA_LEAKAGE, "HTTP (not HTTPS)"),
    "CONF001": (r'insecure[_-]?skip[_-]?verify', Severity.CRITICAL, Category.INSECURE_CONFIG, "TLS Disabled"),
    "COMP001": (r'status:\s*disabled', Severity.CRITICAL, Category.COMPLIANCE_VIOLATION, "Disabled Workflow"),
}

def scan(path: str, suppress=None) -> AuditReport:
    report = AuditReport()
    report.scan_time = datetime.now().isoformat()
    if suppress: report.suppressed_rules = set(suppress)
    
    files = []
    for p in ['*.yml','*.yaml','*.json','*.sh','*.py','*.js','*.ts']:
        files.extend(Path(path).rglob(p))
    report.files_scanned = len(files)
    
    for f in files:
        try:
            with open(str(f), 'r', encoding='utf-8', errors='ignore') as fp:
                content = fp.read()
        except: continue
        
        for rid, (pat, sev, cat, title) in RULES.items():
            if rid in report.suppressed_rules: continue
            if re.search(pat, content, re.IGNORECASE):
                report.findings.append(Finding(rid, sev, cat, title, f"Found: {title}", str(f), f"Fix: {title}"))
    return report

def main():
    p = argparse.ArgumentParser(description='workflow-audit-cli')
    p.add_argument('path', nargs='?', default='.')
    p.add_argument('--format', choices=['text','json'], default='text')
    p.add_argument('--suppress', nargs='+')
    p.add_argument('--output', '-o')
    a = p.parse_args()
    
    r = scan(a.path, a.suppress)
    
    if a.format == 'json':
        print(json.dumps({'scan_time': r.scan_time, 'files': r.files_scanned, 'findings': r.total, 'by_severity': r.by_severity}, indent=2))
    else:
        print(f"\n{'='*50}\n🔒 SECURITY AUDIT\n{'='*50}")
        print(f"Time: {r.scan_time}\nFiles: {r.files_scanned}\nFindings: {r.total}\n")
        for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']:
            print(f"  {s}: {r.by_severity.get(s,0)}")
        print(f"\n{'='*50}\n")

if __name__ == '__main__': main()
