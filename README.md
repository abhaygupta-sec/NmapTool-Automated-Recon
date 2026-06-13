# NmapTool

Automated 6-phase Nmap scan & report generator.

**Phases:** TCP Discovery → TCP Deep → TCP Vuln → UDP Discovery → UDP Deep → UDP Vuln

## Platform Support

- **Linux (including Kali Linux)** — fully supported and the primary target platform.
- **Other platforms** — the script may run anywhere Python 3 and `nmap` are installed,
  but it has only been tested on Linux. Path handling and behavior on Windows are
  not officially supported.

## Privileges

Some nmap scan types (e.g. SYN scans `-sS`, OS detection) require elevated
privileges. This script does **not** elevate itself. If your scan options
require it, run the script with the appropriate privileges yourself, e.g.:

```bash
sudo python3 nmaptool.py <target>
```

## UDP Scans

UDP scans (Phases 4-6) are inherently much slower than TCP scans and can take
a long time on larger targets or port ranges. The tool logs periodic
"still running" progress messages during long-running phases so it's clear
the scan has not frozen.

## Usage

```bash
python3 nmaptool.py 192.168.1.1
python3 nmaptool.py 10.0.0.1 10.0.0.2 172.16.0.5
python3 nmaptool.py 192.168.1.0/24
python3 nmaptool.py -o /tmp/scans 192.168.1.1
```

## Output

For each target, the tool creates a directory containing per-phase HTML
reports, raw output text files, the nmap XML results, a final consolidated
HTML report (`report.html`), and a `summary.json` summary file.
