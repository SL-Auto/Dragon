"""Native secondary translations for the single-event Ligolo-ng rules.

The three multi-event correlation rules (fan-out and listener) use generator candidate retrieval
(`scripts/translate-yaral.ps1`); their exceptions are recorded in reviews/ligolo-ng/translation-review.md.
"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

D = pathlib.Path(__file__).resolve().parents[2] / "detections"
WIN = {"product": "windows"}

PING = r"""^"?([a-z]:\\[^"]*\\)?ping(\.exe)?"?\s+/n\s+1\s+/w\s+3000\s+\S+\s*$|^(\S*/)?ping\s+-c\s+1\s+-W\s+3\s+\S+\s*$"""
SHELL = r"(\\(cmd|powershell|pwsh|wscript|cscript)\.exe|/(ba|z|da|k|c|tc|fi)?sh)$"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
BROWSER = r"\\(chrome|msedge|brave|opera|vivaldi|firefox)\.exe$"
# Text approximation of the canonical net.ip_in_range_cidr checks (10/8, 172.16/12, 192.168/16, fc00::/7).
INTERNAL = r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|f[cd][0-9a-f]{2}:)"
CONNECT = r"""(^|\s)-{1,2}connect(\s+|=)"?\S+"""
TRUST = r"""(^|\s)-{1,2}(ignore-cert(\s|=|$)|accept-fingerprint(\s+|=)"?[0-9a-f]{64})"""

ligolo = [
 dict(name="ligolo_agent_ping_probe_children", kind="single", window=10, keys=["hostname", "parent_process_id"], count=("command_line", 3), values=["parent_process_path"],
      columns=["event_type", "hostname", "parent_process_id", "parent_process_path", "command_line"],
      legs=[dict(where=[("eq","event_type","PROCESS_LAUNCH"),("re","command_line",PING),("notre","parent_process_path",SHELL)])],
      sigma=dict(category="process_creation", **WIN)),
 dict(name="ligolo_websocket_default_user_agent", kind="single", window=60, keys=["source_ip"], count=("#", 1), values=["target_host", "process_path"],
      columns=["event_type", "source_ip", "user_agent", "target_host", "process_path"],
      legs=[dict(where=[("eq","event_type","NETWORK_HTTP"),("eq","user_agent",UA),("notre","process_path",BROWSER)])],
      sigma=dict(category="proxy")),
 # Added after public comparison (LG-DR-10, LG-DR-11).
 dict(name="ligolo_process_internal_admin_port_sweep", kind="single", window=10, keys=["hostname", "process_id"], count=("target_ip", 30), values=["process_path", "target_port"],
      columns=["event_type", "direction", "hostname", "process_id", "process_path", "target_ip", "target_port", "process_signed"],
      legs=[dict(where=[("eq","event_type","NETWORK_CONNECTION"),("eq","direction","OUTBOUND"),
                        ("in","target_port",["21","22","23","135","139","445","3389","5985","5986"]),
                        ("re","target_ip",INTERNAL),("ne_true","process_signed")])],
      sigma=dict(category="network_connection", **WIN)),
 dict(name="ligolo_agent_command_line_trust_flags", kind="single", window=60, keys=["hostname", "process_path"], count=("#", 1), values=["command_line"],
      columns=["event_type", "hostname", "process_path", "command_line"],
      legs=[dict(where=[("eq","event_type","PROCESS_LAUNCH"),("re","command_line",CONNECT),("re","command_line",TRUST)])],
      sigma=dict(category="process_creation", **WIN)),
]

if __name__ == "__main__":
    for sp in ligolo:
        print("ligolo-ng", sp["name"], render(D / "ligolo-ng", sp))
