# workflow-audit-cli

Enhanced CLI for Workflow Security Auditing with advanced features.

## Features

- **Multiple Output Formats**: text, JSON
- **Rule Suppression**: Skip specific rules
- **Detailed Reporting**: Scan metadata, severity breakdown
- **No Dependencies**: Pure Python standard library

## Usage

```bash
python3 audit.py /path/to/scan
python3 audit.py /path --format json
python3 audit.py /path --suppress PERM001 PERM002
python3 audit.py /path -o report.txt
```

## Detections

- Excessive permissions
- Unsafe commands
- Secret exposure
- Data leakage
- Insecure configuration
- Compliance violations
