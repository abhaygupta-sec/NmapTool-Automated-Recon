#!/usr/bin/env python3
"""
NmapTool - Automated Nmap Scan & Report Generator
Made by Abhay Gupta
Phases: TCP Discovery → TCP Deep → TCP Vuln → UDP Discovery → UDP Deep → UDP Vuln

Note: This tool requires nmap to be run with elevated privileges for SYN scans,
OS detection, and some scripts (-sS, -O, etc.). Run this script with sudo /
as Administrator if required by your scan options, e.g.:
    sudo python3 nmaptool.py <target>

Platform: Designed and tested on Linux (Kali Linux recommended). May work on
other platforms where nmap is installed, but is not officially supported on
Windows.
"""

import argparse
import ipaddress
import json
import logging
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

TOOL_AUTHOR  = "Abhay Gupta"
TOOL_VERSION = "1.0"
TOOL_NAME    = "NmapTool"

BANNER = f"""
╔════════════════════════════════════════════════════════════════╗
║          {TOOL_NAME} v{TOOL_VERSION} — Automated Nmap Scanner                  ║
║                      Made by {TOOL_AUTHOR}                         ║
║  TCP Disc → TCP Deep → TCP Vuln → UDP Disc → UDP Deep → UDP Vuln ║
╚════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────── LOGGING SETUP ───────────────────────────

def setup_logging(log_path: Path) -> logging.Logger:
    logger = logging.getLogger("nmaptool")
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger
    fmt = logging.Formatter("%(asctime)s  [%(levelname)s]  %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(log_path)
    fh.setFormatter(fmt)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.propagate = False
    return logger


# ─────────────────────────── IP VALIDATION ───────────────────────────

def validate_targets(targets: list) -> list:
    valid = []
    for t in targets:
        t = t.strip()
        try:
            ipaddress.ip_network(t, strict=False)
            valid.append(t)
        except ValueError:
            print(f"[!] Invalid IP / CIDR skipped: {t}")
    if not valid:
        print("[-] No valid targets. Exiting.")
        sys.exit(1)
    return valid


# ─────────────────────────── XML PARSING ─────────────────────────────

def parse_hostnames(host_el) -> list:
    """Extract all hostnames/PTR records from a host element."""
    names = []
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        for hn in hostnames_el.findall("hostname"):
            name = hn.get("name", "").strip()
            htype = hn.get("type", "")
            if name:
                names.append({"name": name, "type": htype})
    return names


def parse_open_ports(xml_file: Path, protocol: str = "tcp") -> list:
    if not xml_file.exists():
        return []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        ports = []
        for host in root.findall("host"):
            for port in host.findall(f".//port[@protocol='{protocol}']"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    ports.append(port.get("portid"))
        return ports
    except ET.ParseError:
        return []


def parse_scan_meta(xml_file: Path) -> dict:
    """Extract scan metadata: start time, command, nmap version, etc."""
    meta = {"command": "", "version": "", "start": "", "elapsed": ""}
    if not xml_file.exists():
        return meta
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        meta["version"] = root.get("version", "")
        meta["command"] = root.get("args", "")
        ts = root.get("start", "")
        if ts:
            meta["start"] = datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
        run_stats = root.find("runstats/finished")
        if run_stats is not None:
            meta["elapsed"] = run_stats.get("elapsed", "")
            meta["summary"] = run_stats.get("summary", "")
    except Exception:
        pass
    return meta


def parse_full_results(xml_file: Path) -> dict:
    results = {"hosts": []}
    if not xml_file.exists():
        return results
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall("host"):
            host_data = {
                "address": "",
                "mac": "",
                "mac_vendor": "",
                "hostnames": [],
                "ports": [],
                "os": [],
                "status": ""
            }
            # IP address
            addr = host.find("address[@addrtype='ipv4']")
            if addr is not None:
                host_data["address"] = addr.get("addr", "")
            # MAC address
            mac_el = host.find("address[@addrtype='mac']")
            if mac_el is not None:
                host_data["mac"] = mac_el.get("addr", "")
                host_data["mac_vendor"] = mac_el.get("vendor", "")
            # Hostnames / domain names
            host_data["hostnames"] = parse_hostnames(host)
            # Host status
            status_el = host.find("status")
            if status_el is not None:
                host_data["status"] = status_el.get("state", "")
            # OS detection
            for osmatch in host.findall(".//osmatch"):
                host_data["os"].append({
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", "")
                })
            # Ports
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                port_info = {
                    "portid":   port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state":    state.get("state"),
                    "reason":   state.get("reason", ""),
                    "service":  svc.get("name", "")    if svc is not None else "",
                    "product":  svc.get("product", "") if svc is not None else "",
                    "version":  svc.get("version", "") if svc is not None else "",
                    "extrainfo":svc.get("extrainfo","") if svc is not None else "",
                    "tunnel":   svc.get("tunnel", "")  if svc is not None else "",
                    "hostname": svc.get("hostname", "") if svc is not None else "",
                    "scripts":  []
                }
                for script in port.findall("script"):
                    port_info["scripts"].append({
                        "id":     script.get("id", ""),
                        "output": script.get("output", "")
                    })
                host_data["ports"].append(port_info)
            results["hosts"].append(host_data)
    except ET.ParseError:
        pass
    return results


def parse_vuln_results(xml_file: Path) -> list:
    vulns = []
    if not xml_file.exists():
        return vulns
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall("host"):
            addr = host.find("address[@addrtype='ipv4']")
            ip = addr.get("addr", "?") if addr is not None else "?"
            hostnames = parse_hostnames(host)
            for port in host.findall(".//port"):
                portid = port.get("portid")
                proto  = port.get("protocol")
                for script in port.findall("script"):
                    sid = script.get("id", "")
                    out = script.get("output", "").strip()
                    if out and "VULNERABLE" in out.upper():
                        vulns.append({
                            "ip": ip,
                            "hostnames": hostnames,
                            "port": portid,
                            "protocol": proto,
                            "script": sid,
                            "output": out
                        })
    except ET.ParseError:
        pass
    return vulns


# ─────────────────────────── SCAN RUNNER ─────────────────────────────

def run_scan(cmd: list, phase: str, logger: logging.Logger) -> tuple:
    """Run an nmap command. Returns (ok, elapsed, cmd_str, stdout_text)."""
    import threading

    logger.info(f"Starting phase: {phase}")
    logger.info(f"Command: {' '.join(cmd)}")
    start = time.time()

    stop_event = threading.Event()

    def heartbeat():
        while not stop_event.wait(60):
            elapsed_now = time.time() - start
            logger.info(f"[{phase}] Still running... ({elapsed_now/60:.1f} min elapsed). "
                         f"This is normal for UDP or large scans — please wait.")

    hb_thread = threading.Thread(target=heartbeat, daemon=True)
    hb_thread.start()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - start
        combined = ""
        if result.stdout:
            combined += result.stdout
        if result.stderr:
            combined += "\n--- STDERR ---\n" + result.stderr
        if result.returncode != 0:
            logger.warning(f"Phase '{phase}' exited with code {result.returncode}")
            if result.stderr:
                logger.debug(f"STDERR: {result.stderr.strip()}")
            return False, elapsed, " ".join(cmd), combined
        logger.info(f"Phase '{phase}' completed in {elapsed:.1f}s")
        return True, elapsed, " ".join(cmd), combined
    except FileNotFoundError:
        logger.error("nmap not found. Please install nmap first.")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        sys.exit(0)
    finally:
        stop_event.set()


def save_phase_output(scan_dir: Path, phase_num: int, phase_name: str,
                      cmd_str: str, output_text: str, elapsed: float, cached: bool = False):
    """Save raw command output to a .txt file in the scan directory."""
    txt_path = scan_dir / f"phase{phase_num}_output.txt"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = (
        f"{'='*70}\n"
        f"  NmapTool — Phase {phase_num}: {phase_name}\n"
        f"  Generated : {ts}\n"
        f"  Command   : {cmd_str}\n"
        f"  Duration  : {elapsed:.1f}s\n"
        f"{'='*70}\n\n"
    )
    if cached:
        body = "[INFO] This phase was loaded from cache (XML already existed). No command was re-run.\n"
    elif output_text:
        body = output_text
    else:
        body = "[INFO] No output captured.\n"
    txt_path.write_text(header + body)
    return txt_path


# ─────────────────────────── SHARED HTML STYLES ──────────────────────

def base_css() -> str:
    return """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }
header { background: linear-gradient(135deg, #161b22, #21262d); padding: 28px 40px; border-bottom: 1px solid #30363d; }
header h1 { font-size: 1.8rem; color: #58a6ff; letter-spacing: 1px; }
header .sub { color: #8b949e; margin-top: 6px; font-size: 0.9rem; }
header .author { color: #3fb950; font-weight: 600; font-size: 0.85rem; margin-top: 4px; }
.container { max-width: 1300px; margin: 0 auto; padding: 28px 24px; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-bottom: 36px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 18px; text-align: center; }
.card .num  { font-size: 2rem; font-weight: 700; color: #58a6ff; }
.card .label{ color: #8b949e; font-size: 0.82rem; margin-top: 4px; }
.card.danger .num { color: #f85149; }
.card.warn   .num { color: #d29922; }
.card.ok     .num { color: #3fb950; }
.card.purple .num { color: #bc8cff; }
section { margin-bottom: 36px; }
section h2 { font-size: 1.15rem; color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; margin-bottom: 14px; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: #21262d; color: #8b949e; padding: 9px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #30363d; }
td { padding: 8px 12px; border-bottom: 1px solid #21262d; vertical-align: top; word-break: break-word; }
tr:hover td { background: #161b22; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.76rem; font-weight: 600; margin: 1px; }
.open   { background: #1a3a1a; color: #3fb950; }
.tcp    { background: #1a2a3a; color: #58a6ff; }
.udp    { background: #2a1a3a; color: #bc8cff; }
.dns    { background: #1a2a1a; color: #7ee787; }
.ptr    { background: #2a2a1a; color: #e3b341; }
.user   { background: #2a1a1a; color: #f85149; }
.vuln-block { background: #1a1218; border: 1px solid #6e2030; border-radius: 8px; padding: 14px; margin-bottom: 12px; }
.vuln-block .vuln-header { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.vuln-block .vuln-title  { color: #f85149; font-weight: 700; }
.vuln-block pre { background: #0d1117; border-radius: 6px; padding: 10px; font-size: 0.78rem; white-space: pre-wrap; color: #c9d1d9; border: 1px solid #30363d; overflow-x: auto; max-height: 300px; overflow-y: auto; }
.script-out { background: #0d1117; border-radius: 4px; padding: 6px 8px; font-size: 0.76rem; color: #8b949e; margin-top: 4px; white-space: pre-wrap; max-height: 100px; overflow-y: auto; }
.scan-meta  { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 18px; margin-bottom: 24px; font-size: 0.84rem; }
.scan-meta .meta-row { display: flex; gap: 8px; margin-bottom: 5px; flex-wrap: wrap; }
.scan-meta .meta-key  { color: #8b949e; min-width: 130px; }
.scan-meta .meta-val  { color: #e6edf3; font-family: monospace; word-break: break-all; }
.phase-nav { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 28px; }
.phase-nav a { background: #21262d; color: #58a6ff; padding: 6px 14px; border-radius: 6px; text-decoration: none; font-size: 0.83rem; border: 1px solid #30363d; }
.phase-nav a:hover { background: #30363d; }
.no-data { color: #8b949e; font-style: italic; padding: 10px 0; }
footer { text-align: center; padding: 20px; color: #484f58; font-size: 0.8rem; border-top: 1px solid #30363d; margin-top: 36px; }
.hostname-list { display: flex; flex-wrap: wrap; gap: 4px; }
.phase-timeline { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 36px; }
.phase-item { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 18px; flex: 1; min-width: 150px; }
.phase-item .phase-name { font-size: 0.8rem; color: #8b949e; }
.phase-item .phase-time { font-size: 1rem; font-weight: 600; color: #3fb950; margin-top: 4px; }
.phase-item.skipped .phase-time { color: #484f58; }
"""


def make_header(title: str, target: str, subtitle: str = "") -> str:
    return f"""
    <header>
      <h1>🔍 {TOOL_NAME} — {title}</h1>
      <div class="sub">Target: <b>{target}</b>{f' &nbsp;|&nbsp; {subtitle}' if subtitle else ''}</div>
      <div class="author">Made by {TOOL_AUTHOR} &nbsp;|&nbsp; {TOOL_NAME} v{TOOL_VERSION}</div>
    </header>"""


def make_footer() -> str:
    return f"""<footer>
      {TOOL_NAME} v{TOOL_VERSION} &nbsp;|&nbsp; Made by {TOOL_AUTHOR} &nbsp;|&nbsp;
      Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </footer>"""


def render_hostnames(hostnames: list) -> str:
    if not hostnames:
        return '<span class="no-data">—</span>'
    out = '<div class="hostname-list">'
    for h in hostnames:
        cls = "ptr" if h["type"] == "PTR" else "dns" if h["type"] == "user" else "dns"
        out += f'<span class="badge {cls}">{h["name"]} <small>({h["type"]})</small></span>'
    out += '</div>'
    return out


def render_ports_table(hosts: list, protocol: str = "tcp") -> str:
    rows = ""
    for host in hosts:
        for p in host["ports"]:
            if p["protocol"] != protocol:
                continue
            scripts_html = ""
            for s in p["scripts"]:
                scripts_html += f'<div class="script-out"><b>{s["id"]}</b>: {s["output"][:400]}</div>'
            ver = f"{p['product']} {p['version']}".strip()
            if p.get("extrainfo"):
                ver += f" ({p['extrainfo']})"
            hn_html = render_hostnames(host["hostnames"])
            rows += f"""<tr>
                <td>{host['address']}</td>
                <td>{hn_html}</td>
                <td><span class="badge {protocol}">{p['portid']}/{protocol}</span></td>
                <td><span class="badge open">{p['state']}</span></td>
                <td>{p['service']}</td>
                <td>{ver or '—'}</td>
                <td>{scripts_html or '—'}</td>
            </tr>"""
    if not rows:
        rows = f'<tr><td colspan="7" class="no-data">No open {protocol.upper()} ports found.</td></tr>'
    return f"""<table>
      <thead><tr>
        <th>IP</th><th>Hostname / Domain</th><th>Port</th><th>State</th>
        <th>Service</th><th>Version / Product</th><th>Scripts</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def render_scan_meta(meta: dict, cmd_used: str = "") -> str:
    rows = ""
    fields = [
        ("Nmap Version", meta.get("version", "—")),
        ("Scan Started", meta.get("start", "—")),
        ("Elapsed",      (meta.get("elapsed", "") + "s") if meta.get("elapsed") else "—"),
        ("Summary",      meta.get("summary", "—")),
        ("Command",      cmd_used or meta.get("command", "—")),
    ]
    for k, v in fields:
        rows += f'<div class="meta-row"><span class="meta-key">{k}:</span><span class="meta-val">{v}</span></div>'
    return f'<div class="scan-meta">{rows}</div>'


def render_vuln_blocks(vulns: list) -> str:
    if not vulns:
        return '<p class="no-data">No confirmed vulnerabilities found.</p>'
    out = ""
    for v in vulns:
        hn_html = render_hostnames(v.get("hostnames", []))
        out += f"""<div class="vuln-block">
          <div class="vuln-header">
            <span class="badge tcp">{v['ip']}:{v['port']}/{v['protocol']}</span>
            {hn_html}
            <span class="vuln-title">{v['script']}</span>
          </div>
          <pre>{v['output'][:2000]}</pre>
        </div>"""
    return out


# ─────────────────────────── PER-PHASE REPORT ────────────────────────

def write_phase_report(
    path: Path,
    target: str,
    phase_name: str,
    phase_num: int,
    xml_file: Path,
    cmd_used: str,
    elapsed: float,
    results: dict = None,
    open_ports: list = None,
    vulns: list = None,
    protocol: str = "tcp",
    skipped: bool = False,
    raw_output: str = "",
    output_txt_name: str = ""
):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta = parse_scan_meta(xml_file)
    if not meta.get("command") and cmd_used:
        meta["command"] = cmd_used
    if not meta.get("elapsed") and elapsed:
        meta["elapsed"] = f"{elapsed:.1f}"

    ports_section = ""
    if results:
        ports_section = f"""
        <section>
          <h2>📋 Open Ports Found</h2>
          {render_ports_table(results.get('hosts', []), protocol)}
        </section>"""

    vuln_section = ""
    if vulns is not None:
        vuln_section = f"""
        <section>
          <h2>⚠️ Vulnerability Findings</h2>
          {render_vuln_blocks(vulns)}
        </section>"""

    open_count = len(open_ports) if open_ports else 0
    vuln_count = len(vulns) if vulns else 0

    skipped_banner = ""
    if skipped:
        skipped_banner = '<div style="background:#1a1a0a;border:1px solid #d29922;border-radius:8px;padding:14px;margin-bottom:24px;color:#d29922;">⚠️ This phase was skipped (no open ports from previous phase).</div>'

    # Raw output section
    raw_output_section = ""
    if raw_output or output_txt_name:
        escaped = (raw_output or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        dl_link = f'<a href="{output_txt_name}" style="color:#58a6ff;font-size:0.82rem;margin-left:12px;">⬇ Download raw output (.txt)</a>' if output_txt_name else ""
        raw_output_section = f"""
        <section>
          <h2>🖥 Raw Command Output {dl_link}</h2>
          <pre style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:14px;font-size:0.78rem;white-space:pre-wrap;max-height:400px;overflow-y:auto;color:#c9d1d9;">{escaped or '[No output captured — phase may have been loaded from cache]'}</pre>
        </section>"""

    # Hostname summary table
    host_table = ""
    if results and results.get("hosts"):
        rows = ""
        for h in results["hosts"]:
            hn_html = render_hostnames(h["hostnames"])
            mac_info = f'{h["mac"]}' + (f' ({h["mac_vendor"]})' if h["mac_vendor"] else '') if h["mac"] else "—"
            os_str = ", ".join(f'{o["name"]} ({o["accuracy"]}%)' for o in h["os"]) or "—"
            rows += f"""<tr>
              <td>{h['address']}</td>
              <td>{hn_html}</td>
              <td>{mac_info}</td>
              <td>{os_str}</td>
              <td><span class="badge open">{h['status']}</span></td>
            </tr>"""
        host_table = f"""
        <section>
          <h2>🖥 Host Information</h2>
          <table>
            <thead><tr><th>IP Address</th><th>Hostname / Domain</th><th>MAC Address</th><th>OS Detection</th><th>Status</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </section>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{TOOL_NAME} — Phase {phase_num}: {phase_name} — {target}</title>
<style>{base_css()}</style>
</head>
<body>
{make_header(f'Phase {phase_num}: {phase_name}', target, f'Completed: {ts}')}
<div class="container">

  <div class="summary-grid">
    <div class="card"><div class="num">{phase_num}/6</div><div class="label">Phase</div></div>
    <div class="card {'ok' if open_count else ''}"><div class="num">{open_count}</div><div class="label">Open Ports</div></div>
    <div class="card {'danger' if vuln_count else 'ok'}"><div class="num">{vuln_count}</div><div class="label">Vulns Found</div></div>
    <div class="card"><div class="num">{elapsed:.1f}s</div><div class="label">Duration</div></div>
  </div>

  <section>
    <h2>🔧 Scan Details</h2>
    {render_scan_meta(meta, cmd_used)}
  </section>

  {skipped_banner}
  {host_table}
  {ports_section}
  {vuln_section}
  {raw_output_section}

</div>
{make_footer()}
</body>
</html>"""
    path.write_text(html)


# ─────────────────────────── FINAL REPORT ────────────────────────────

def write_final_report(
    path: Path,
    target: str,
    scan_dir: Path,
    phases: list,
    tcp_deep: dict,
    udp_deep: dict,
    tcp_vulns: list,
    udp_vulns: list,
    open_tcp: list,
    open_udp: list,
    start_time: datetime
):
    total_tcp       = len(open_tcp)
    total_udp       = len(open_udp)
    total_tcp_vuln  = len(tcp_vulns)
    total_udp_vuln  = len(udp_vulns)
    total_vuln      = total_tcp_vuln + total_udp_vuln
    vulns           = tcp_vulns  # keep backward-compat alias for the host-summary block

    # Phase timeline
    phase_html = ""
    for ph in phases:
        skip_cls = "skipped" if ph["skipped"] else ""
        t_str = f"{ph['elapsed']:.1f}s" if not ph["skipped"] else "Skipped"
        phase_html += f"""
        <div class="phase-item {skip_cls}">
          <div class="phase-name">Phase {ph['num']}: {ph['name']}</div>
          <div class="phase-time">{t_str}</div>
        </div>"""

    # Phase nav links
    nav_html = ""
    for ph in phases:
        nav_html += f'<a href="{ph["report"]}">Phase {ph["num"]}: {ph["name"]}</a>'

    # Host summary
    all_hosts = {}
    for host in tcp_deep.get("hosts", []) + udp_deep.get("hosts", []):
        ip = host["address"]
        if ip not in all_hosts:
            all_hosts[ip] = host
        else:
            all_hosts[ip]["ports"].extend(host["ports"])

    host_rows = ""
    for ip, h in all_hosts.items():
        hn_html = render_hostnames(h["hostnames"])
        mac_info = f'{h["mac"]}' + (f' ({h["mac_vendor"]})' if h["mac_vendor"] else '') if h["mac"] else "—"
        os_str   = ", ".join(f'{o["name"]} ({o["accuracy"]}%)' for o in h["os"]) or "—"
        tcp_p = [p["portid"] for p in h["ports"] if p["protocol"] == "tcp"]
        udp_p = [p["portid"] for p in h["ports"] if p["protocol"] == "udp"]
        host_rows += f"""<tr>
          <td>{ip}</td>
          <td>{hn_html}</td>
          <td>{mac_info}</td>
          <td>{os_str}</td>
          <td>{', '.join(tcp_p) or '—'}</td>
          <td>{', '.join(udp_p) or '—'}</td>
        </tr>"""

    if not host_rows:
        host_rows = '<tr><td colspan="6" class="no-data">No hosts enumerated.</td></tr>'

    tcp_vuln_cls = "danger" if total_tcp_vuln > 0 else "ok"
    udp_vuln_cls = "danger" if total_udp_vuln > 0 else "ok"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{TOOL_NAME} — Full Report — {target}</title>
<style>{base_css()}</style>
</head>
<body>
{make_header('Full Scan Report', target, f'Started: {start_time.strftime("%Y-%m-%d %H:%M:%S")}')}
<div class="container">

  <div class="summary-grid">
    <div class="card ok">      <div class="num">{total_tcp}</div>       <div class="label">Open TCP Ports</div></div>
    <div class="card purple">  <div class="num">{total_udp}</div>       <div class="label">Open UDP Ports</div></div>
    <div class="card {tcp_vuln_cls}"><div class="num">{total_tcp_vuln}</div><div class="label">TCP Vulnerabilities</div></div>
    <div class="card {udp_vuln_cls}"><div class="num">{total_udp_vuln}</div><div class="label">UDP Vulnerabilities</div></div>
    <div class="card warn">    <div class="num">{total_vuln}</div>      <div class="label">Total Vulns</div></div>
    <div class="card">         <div class="num">{len(all_hosts)}</div>  <div class="label">Hosts Discovered</div></div>
  </div>

  <section>
    <h2>📂 Phase Reports</h2>
    <div class="phase-nav">{nav_html}</div>
    <div class="phase-timeline">{phase_html}</div>
  </section>

  <section>
    <h2>🖥 Host Overview</h2>
    <table>
      <thead><tr>
        <th>IP Address</th><th>Hostname / Domain</th><th>MAC Address</th>
        <th>OS Detection</th><th>TCP Open Ports</th><th>UDP Open Ports</th>
      </tr></thead>
      <tbody>{host_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>🔓 TCP Ports — Full Detail</h2>
    {render_ports_table(tcp_deep.get('hosts', []), 'tcp')}
  </section>

  <section>
    <h2>📡 UDP Ports — Full Detail</h2>
    {render_ports_table(udp_deep.get('hosts', []), 'udp')}
  </section>

  <section>
    <h2>⚠️ TCP Vulnerability Findings</h2>
    {render_vuln_blocks(tcp_vulns)}
  </section>

  <section>
    <h2>⚠️ UDP Vulnerability Findings</h2>
    {render_vuln_blocks(udp_vulns)}
  </section>

</div>
{make_footer()}
</body>
</html>"""
    path.write_text(html)


# ─────────────────────────── MAIN SCAN LOGIC ─────────────────────────

def scan_target(target: str, base_dir: Path, logger: logging.Logger):
    safe_name = target.replace("/", "_").replace(".", "-")
    scan_dir  = base_dir / safe_name
    scan_dir.mkdir(parents=True, exist_ok=True)

    start_time = datetime.now()
    phases = []
    logger.info(f"{'='*60}")
    logger.info(f"Target: {target}  |  Output: {scan_dir}")
    logger.info(f"{'='*60}")

    # ── Phase 1: TCP Discovery ──────────────────────────────────────
    tcp1_xml = scan_dir / "target1.xml"
    p1_cmd   = ["nmap","--top-ports","10000","-sS","-T4","-Pn","-n","-oX",str(tcp1_xml),target]
    cached1  = tcp1_xml.exists()
    if cached1:
        logger.info("[Phase 1] Cached — skipping TCP discovery.")
        elapsed, cmd_str, raw1 = 0.0, " ".join(p1_cmd), ""
        ok = True
    else:
        ok, elapsed, cmd_str, raw1 = run_scan(p1_cmd, "Phase 1: TCP Discovery", logger)

    txt1 = save_phase_output(scan_dir, 1, "TCP Discovery", cmd_str, raw1, elapsed, cached=cached1)
    open_tcp   = parse_open_ports(tcp1_xml, "tcp")
    logger.info(f"Open TCP ports: {open_tcp or 'None'}")
    p1_results = parse_full_results(tcp1_xml)
    p1_report  = scan_dir / "phase1_tcp_discovery.html"
    write_phase_report(p1_report, target, "TCP Discovery", 1, tcp1_xml, cmd_str, elapsed,
                       results=p1_results, open_ports=open_tcp, protocol="tcp", skipped=not ok,
                       raw_output=raw1, output_txt_name=txt1.name)
    logger.info(f"Phase 1 report : {p1_report}")
    logger.info(f"Phase 1 output : {txt1}")
    phases.append({"num":1,"name":"TCP Discovery","skipped":not ok,"elapsed":elapsed,"report":p1_report.name})

    # ── Phase 2: TCP Deep Scan ──────────────────────────────────────
    tcp2_xml  = scan_dir / "target2.xml"
    ports_str = ",".join(open_tcp)
    p2_cmd    = ["nmap","-p",ports_str,"-sC","-sV","-sS","-T4","-Pn","-n","-oX",str(tcp2_xml),target]
    if not open_tcp:
        logger.warning("[Phase 2] No open TCP ports — skipping.")
        elapsed2, cmd2_str, raw2, skipped2 = 0.0, " ".join(p2_cmd), "", True
    elif tcp2_xml.exists():
        logger.info("[Phase 2] Cached — skipping TCP deep scan.")
        elapsed2, cmd2_str, raw2, skipped2 = 0.0, " ".join(p2_cmd), "", False
    else:
        ok2, elapsed2, cmd2_str, raw2 = run_scan(p2_cmd, "Phase 2: TCP Deep Scan", logger)
        skipped2 = not ok2

    txt2 = save_phase_output(scan_dir, 2, "TCP Deep Scan", cmd2_str, raw2, elapsed2,
                             cached=(tcp2_xml.exists() and not raw2))
    p2_results = parse_full_results(tcp2_xml)
    p2_report  = scan_dir / "phase2_tcp_deep.html"
    write_phase_report(p2_report, target, "TCP Deep Scan", 2, tcp2_xml, cmd2_str, elapsed2,
                       results=p2_results, open_ports=open_tcp, protocol="tcp", skipped=skipped2,
                       raw_output=raw2, output_txt_name=txt2.name)
    logger.info(f"Phase 2 report : {p2_report}")
    logger.info(f"Phase 2 output : {txt2}")
    phases.append({"num":2,"name":"TCP Deep Scan","skipped":skipped2,"elapsed":elapsed2,"report":p2_report.name})

    # ── Phase 3: TCP Vulnerability Scan ───────────────────────────
    tcp3_xml = scan_dir / "target3.xml"
    p3_cmd   = ["nmap","-p",ports_str,"--script","vuln","-sS","-T4","-Pn","-n","-oX",str(tcp3_xml),target]
    if not open_tcp:
        logger.warning("[Phase 3] No open TCP ports — skipping.")
        elapsed3, cmd3_str, raw3, skipped3 = 0.0, " ".join(p3_cmd), "", True
    elif tcp3_xml.exists():
        logger.info("[Phase 3] Cached — skipping TCP vuln scan.")
        elapsed3, cmd3_str, raw3, skipped3 = 0.0, " ".join(p3_cmd), "", False
    else:
        ok3, elapsed3, cmd3_str, raw3 = run_scan(p3_cmd, "Phase 3: TCP Vuln Scan", logger)
        skipped3 = not ok3

    txt3  = save_phase_output(scan_dir, 3, "TCP Vulnerability Scan", cmd3_str, raw3, elapsed3,
                              cached=(tcp3_xml.exists() and not raw3))
    vulns = parse_vuln_results(tcp3_xml)
    p3_report = scan_dir / "phase3_vuln_scan.html"
    write_phase_report(p3_report, target, "TCP Vulnerability Scan", 3, tcp3_xml, cmd3_str, elapsed3,
                       open_ports=open_tcp, vulns=vulns, protocol="tcp", skipped=skipped3,
                       raw_output=raw3, output_txt_name=txt3.name)
    logger.info(f"Phase 3 report : {p3_report}")
    logger.info(f"Phase 3 output : {txt3}")
    phases.append({"num":3,"name":"TCP Vulnerability Scan","skipped":skipped3,"elapsed":elapsed3,"report":p3_report.name})

    # ── Phase 4: UDP Discovery ─────────────────────────────────────
    udp1_xml = scan_dir / "udp.xml"
    p4_cmd   = ["nmap","-sU","--top-ports","100","-T4","-Pn","-n","-oX",str(udp1_xml),target]
    cached4  = udp1_xml.exists()
    if cached4:
        logger.info("[Phase 4] Cached — skipping UDP discovery.")
        elapsed4, cmd4_str, raw4 = 0.0, " ".join(p4_cmd), ""
        skipped4 = False
    else:
        logger.info("[Phase 4] UDP scans can be significantly slower than TCP scans. "
                     "This may take a while depending on the target — please be patient.")
        ok4, elapsed4, cmd4_str, raw4 = run_scan(p4_cmd, "Phase 4: UDP Discovery", logger)
        skipped4 = not ok4

    txt4 = save_phase_output(scan_dir, 4, "UDP Discovery", cmd4_str, raw4, elapsed4, cached=cached4)
    open_udp   = parse_open_ports(udp1_xml, "udp")
    logger.info(f"Open UDP ports: {open_udp or 'None'}")
    p4_results = parse_full_results(udp1_xml)
    p4_report  = scan_dir / "phase4_udp_discovery.html"
    write_phase_report(p4_report, target, "UDP Discovery", 4, udp1_xml, cmd4_str, elapsed4,
                       results=p4_results, open_ports=open_udp, protocol="udp", skipped=skipped4,
                       raw_output=raw4, output_txt_name=txt4.name)
    logger.info(f"Phase 4 report : {p4_report}")
    logger.info(f"Phase 4 output : {txt4}")
    phases.append({"num":4,"name":"UDP Discovery","skipped":skipped4,"elapsed":elapsed4,"report":p4_report.name})

    # ── Phase 5: UDP Deep Scan ─────────────────────────────────────
    udp2_xml  = scan_dir / "udp1.xml"
    udp_ports = ",".join(open_udp)
    p5_cmd    = ["nmap","-sU","-p",udp_ports,"-sC","-sV","-T4","-Pn","-n","-oX",str(udp2_xml),target]
    if not open_udp:
        logger.warning("[Phase 5] No open UDP ports — skipping.")
        elapsed5, cmd5_str, raw5, skipped5 = 0.0, " ".join(p5_cmd), "", True
    elif udp2_xml.exists():
        logger.info("[Phase 5] Cached — skipping UDP deep scan.")
        elapsed5, cmd5_str, raw5, skipped5 = 0.0, " ".join(p5_cmd), "", False
    else:
        logger.info("[Phase 5] UDP scans can be significantly slower than TCP scans. "
                     "This may take a while depending on the target — please be patient.")
        ok5, elapsed5, cmd5_str, raw5 = run_scan(p5_cmd, "Phase 5: UDP Deep Scan", logger)
        skipped5 = not ok5

    txt5 = save_phase_output(scan_dir, 5, "UDP Deep Scan", cmd5_str, raw5, elapsed5,
                             cached=(udp2_xml.exists() and not raw5))
    udp_deep  = parse_full_results(udp2_xml)
    p5_report = scan_dir / "phase5_udp_deep.html"
    write_phase_report(p5_report, target, "UDP Deep Scan", 5, udp2_xml, cmd5_str, elapsed5,
                       results=udp_deep, open_ports=open_udp, protocol="udp", skipped=skipped5,
                       raw_output=raw5, output_txt_name=txt5.name)
    logger.info(f"Phase 5 report : {p5_report}")
    logger.info(f"Phase 5 output : {txt5}")
    phases.append({"num":5,"name":"UDP Deep Scan","skipped":skipped5,"elapsed":elapsed5,"report":p5_report.name})

    # ── Phase 6: UDP Vulnerability Scan ───────────────────────────
    udp3_xml = scan_dir / "udp2.xml"
    p6_cmd   = ["nmap","-sU","-p",udp_ports,"--script","vuln","-T4","-Pn","-n","-oX",str(udp3_xml),target]
    if not open_udp:
        logger.warning("[Phase 6] No open UDP ports — skipping UDP vuln scan.")
        elapsed6, cmd6_str, raw6, skipped6 = 0.0, " ".join(p6_cmd), "", True
    elif udp3_xml.exists():
        logger.info("[Phase 6] Cached — skipping UDP vuln scan.")
        elapsed6, cmd6_str, raw6, skipped6 = 0.0, " ".join(p6_cmd), "", False
    else:
        logger.info("[Phase 6] UDP scans can be significantly slower than TCP scans. "
                     "This may take a while depending on the target — please be patient.")
        ok6, elapsed6, cmd6_str, raw6 = run_scan(p6_cmd, "Phase 6: UDP Vuln Scan", logger)
        skipped6 = not ok6

    txt6       = save_phase_output(scan_dir, 6, "UDP Vulnerability Scan", cmd6_str, raw6, elapsed6,
                                   cached=(udp3_xml.exists() and not raw6))
    udp_vulns  = parse_vuln_results(udp3_xml)
    p6_report  = scan_dir / "phase6_udp_vuln_scan.html"
    write_phase_report(p6_report, target, "UDP Vulnerability Scan", 6, udp3_xml, cmd6_str, elapsed6,
                       open_ports=open_udp, vulns=udp_vulns, protocol="udp", skipped=skipped6,
                       raw_output=raw6, output_txt_name=txt6.name)
    logger.info(f"Phase 6 report : {p6_report}")
    logger.info(f"Phase 6 output : {txt6}")
    phases.append({"num":6,"name":"UDP Vulnerability Scan","skipped":skipped6,"elapsed":elapsed6,"report":p6_report.name})

    # ── Final Report ───────────────────────────────────────────────
    tcp_deep   = parse_full_results(tcp2_xml)
    all_vulns  = vulns + udp_vulns          # TCP + UDP vulns combined
    final_html = scan_dir / "report.html"
    write_final_report(final_html, target, scan_dir, phases, tcp_deep, udp_deep,
                       vulns, udp_vulns, open_tcp, open_udp, start_time)
    logger.info(f"Final HTML report: {final_html}")

    # ── JSON Summary ───────────────────────────────────────────────
    summary = {
        "tool": TOOL_NAME, "author": TOOL_AUTHOR, "version": TOOL_VERSION,
        "target": target,
        "scan_started": start_time.isoformat(),
        "open_tcp_ports": open_tcp,
        "open_udp_ports": open_udp,
        "tcp_vulnerabilities_found": len(vulns),
        "udp_vulnerabilities_found": len(udp_vulns),
        "total_vulnerabilities_found": len(all_vulns),
        "phases": phases
    }
    json_path = scan_dir / "summary.json"
    json_path.write_text(json.dumps(summary, indent=2))

    logger.info(f"{'='*60}")
    logger.info(f"✅ Scan complete for {target}")
    logger.info(f"   Open TCP : {len(open_tcp)} | Open UDP : {len(open_udp)}")
    logger.info(f"   TCP Vulns: {len(vulns)}   | UDP Vulns: {len(udp_vulns)}")
    logger.info(f"   Report   : {final_html}")
    logger.info(f"{'='*60}")


# ─────────────────────────── ENTRY POINT ─────────────────────────────

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} — Automated 6-phase Nmap scanner with per-phase + final HTML reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Made by {TOOL_AUTHOR}

Examples:
  python3 nmaptool.py 192.168.1.1
  python3 nmaptool.py 10.0.0.1 10.0.0.2 172.16.0.5
  python3 nmaptool.py 192.168.1.0/24
  python3 nmaptool.py -o /tmp/scans 192.168.1.1
        """
    )
    parser.add_argument("targets", nargs="+", help="IP addresses or CIDR ranges to scan")
    parser.add_argument("-o","--output", default=str(Path.cwd() / "scans"),
                        help="Base output directory (default: ./scans in current working directory)")
    args = parser.parse_args()

    targets  = validate_targets(args.targets)
    base_dir = Path(args.output)
    base_dir.mkdir(parents=True, exist_ok=True)
    log_path = base_dir / f"nmaptool_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logger   = setup_logging(log_path)

    logger.info(f"{TOOL_NAME} v{TOOL_VERSION} | Made by {TOOL_AUTHOR}")
    logger.info(f"Targets: {targets}")

    for target in targets:
        scan_target(target, base_dir, logger)

    logger.info("All scans complete.")


if __name__ == "__main__":
    main()
