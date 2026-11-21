"""Native secondary translations for the single-event AdaptixC2 rules.

The multi-event correlations (pipe-to-5145, listen-to-inbound, tunnel fan-out, egress-to-child, RWX, archive and
screenshot with egress) use generator candidate retrieval; see reviews/adaptixc2/translation-review.md.
"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

D = pathlib.Path(__file__).resolve().parents[2] / "detections"
WIN = {"product": "windows"}
NC = ["event_type", "direction", "hostname", "process_id", "process_path", "target_ip", "target_port", "ip_protocol", "process_signed"]

adaptix = [
 dict(name="adaptix_raw_socket_dns_from_user_process", kind="single", window=30, keys=["hostname", "process_id"], count=("#", 6), values=["target_ip", "process_path"],
      columns=NC, legs=[dict(where=[("eq","event_type","NETWORK_CONNECTION"),("num","target_port",53),("eq","ip_protocol","UDP"),
      ("notre","process_path",r"\\windows\\system32\\(svchost|dns|lsass)\.exe$"),("ne_true","process_signed")])], sigma=dict(category="network_connection", **WIN)),
 dict(name="adaptix_recurrent_process_egress", kind="single", window=60, keys=["hostname", "process_id", "target_ip"], count=("#", 5), values=["process_path"],
      columns=NC, legs=[dict(where=[("eq","event_type","NETWORK_CONNECTION"),("eq","direction","OUTBOUND"),("ne_true","process_signed")])], sigma=dict(category="network_connection", **WIN)),
 dict(name="adaptix_secondary_logon_hidden_interpreter", kind="single", window=30, keys=["hostname"], count=("#", 1), values=["command_line", "user_id"],
      columns=["event_type", "hostname", "parent_command_line", "process_path", "command_line", "user_id"],
      legs=[dict(where=[("eq","event_type","PROCESS_LAUNCH"),("re","parent_command_line",r"svchost\.exe.*seclogon"),("re","process_path",r"\\(cmd|powershell|pwsh|rundll32|regsvr32|mshta)\.exe$")])],
      sigma=dict(category="process_creation", **WIN)),
]

if __name__ == "__main__":
    for sp in adaptix:
        print("adaptixc2", sp["name"], render(D / "adaptixc2", sp))
