"""Native secondary translations for the 13 Nmap, Ncat and Nping rules (all single-event aggregations)."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

D = pathlib.Path(__file__).resolve().parents[2] / "detections"
WIN = {"product": "windows"}
PC = dict(category="process_creation", **WIN)
NC = dict(category="network_connection", **WIN)

SCAN = r"(^|\s)-s[STUVACNFXWMOYZIL]{1,2}(\s|$)"
SECOND = r"(^|\s)(-p\s*[0-9TU:,-]+|-p-|-Pn|-P[SAUYEPM][0-9,]*|-O(\s|$)|-A(\s|$)|-T[0-5](\s|$)|--top-ports|--script(\s|=)|-o[ANXGS](\s|$)|--min-rate|--max-retries|--open(\s|$))"
SCRIPT = r"(^|\s)--(script|script-args)(\s|=)\S*(vuln|exploit|brute|auth|intrusive|dos|broadcast|discovery|default|safe|[a-z0-9-]+\.nse)"
NPING = r"(^|\s)--(echo-server|echo-client|icmp-type|tcp-connect|arp-type)(\s|=)"
INTERNAL = r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|f[cd][0-9a-f]{2}:)"
SRCINT = r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
NCLONG = r"(^|\s)--(sh-exec|lua-exec|broker|chat|keep-open)(\s|=|$)"
NCEXEC = r"(^|\s)(-e|--exec|-c)(\s|=)\S+"
NCLISTEN = r"(^|\s)(-[nvk]*l[nvkp]*|--listen)(\s|$)"
PORTARG = r"\s\d{2,5}(\s|$)"
SHELL = r"(\\(cmd|powershell|pwsh)\.exe|/(ba|z|da|k)?sh)$"
BIND = r"(^|\s)(-e|--exec|-c|--sh-exec)(\s|=)\S+"
IPPORT = r"(\d{1,3}\.){3}\d{1,3}\s+\d{2,5}(\s|$)"


def s(name, keys, count, where, cols, sigma, values=None, window=60):
    return dict(name=name, kind="single", window=window, keys=keys, count=count, values=values or [], columns=cols, legs=[dict(where=where)], sigma=sigma)


PCC = ["event_type", "hostname", "process_path", "command_line"]
nmap = [
 s("nmap_cli_option_grammar", ["hostname", "process_path"], ("#", 1),
   [("eq","event_type","PROCESS_LAUNCH"),("or",[[("re","command_line",SCAN),("re","command_line",SECOND)],[("re","command_line",SCRIPT)],[("re","command_line",NPING)]])], PCC, PC, ["command_line"]),
 s("nmap_binary_identity_execution", ["hostname", "process_path"], ("#", 1),
   [("eq","event_type","PROCESS_LAUNCH"),("or",[[("re","original_file_name",r"^nmap\.exe$")],[("re","process_path",r"(\\nmap\.exe|/nmap)$")]])], PCC + ["original_file_name"], PC, ["command_line"]),
 s("nmap_process_connect_scan_fanout", ["hostname", "process_id"], ("target_ip", 50),
   [("eq","event_type","NETWORK_CONNECTION"),("eq","direction","OUTBOUND"),("re","target_ip",INTERNAL),("ne_true","process_signed")],
   ["event_type", "direction", "hostname", "process_id", "process_path", "target_ip", "target_port", "process_signed"], NC, ["target_port", "process_path"], window=5),
 s("nmap_network_scan_flow_pattern", ["source_ip"], ("target_ip", 100),
   [("in","event_type",["NETWORK_CONNECTION","NETWORK_FLOW"]),("re","source_ip",SRCINT)], ["event_type", "source_ip", "target_ip", "target_port"], dict(category="firewall"), ["target_port"], window=5),
 s("nmap_reverse_dns_ptr_burst", ["hostname", "process_id"], ("dns_query", 100),
   [("eq","event_type","NETWORK_DNS"),("re","dns_query",r"\.(in-addr|ip6)\.arpa\.?$")], ["event_type", "hostname", "process_id", "process_path", "dns_query"], dict(category="dns_query", **WIN), ["process_path"], window=5),
 s("nmap_nse_http_default_user_agent", ["source_ip"], ("#", 1),
   [("eq","event_type","NETWORK_HTTP"),("re","user_agent","Nmap Scripting Engine")], ["event_type", "source_ip", "user_agent", "target_host"], dict(category="webserver"), ["target_host"]),
 s("nmap_auth_failure_fanout_from_source", ["source_ip"], ("target_user", 10),
   [("or",[[("in","product_event_type",["4625","4771"])],[("eq","event_type","USER_LOGIN"),("eq","action","BLOCK")]])],
   ["event_type", "product_event_type", "source_ip", "target_user", "target_host", "action"], dict(service="security", **WIN), ["target_host"], window=10),
 s("nmap_broadcast_discovery_ports", ["hostname", "process_id"], ("target_port", 4),
   [("eq","event_type","NETWORK_CONNECTION"),("in","target_port",["5355","5353","1900","137","67","3702","427"]),
    ("notre","process_path",r"\\windows\\system32\\(svchost|lsass|services|dashost)\.exe$")],
   ["event_type", "hostname", "process_id", "process_path", "target_port"], NC, ["process_path"], window=2),
 s("nmap_output_file_artifacts", ["hostname"], ("#", 1),
   [("eq","event_type","FILE_CREATION"),("re","target_path",r"\.gnmap$")], ["event_type", "hostname", "target_path", "process_path"], dict(category="file_event", **WIN), ["target_path", "process_path"]),
 s("nmap_npcap_driver_install", ["hostname"], ("#", 1),
   [("or",[[("eq","product_event_type","7045"),("re","service_name",r"^npcap")],[("eq","product_event_type","6"),("re","target_path",r"\\npcap\.sys$")],[("eq","product_event_type","6"),("re","signer",r"Insecure\.Com")]])],
   ["product_event_type", "hostname", "service_name", "target_path", "signer"], dict(service="system", **WIN), ["target_path"]),
 s("nmap_tcpip_performance_tweak", ["hostname"], ("#", 1),
   [("or",[[("eq","event_type","REGISTRY_MODIFICATION"),("re","registry_key",r"\\Services\\Tcpip\\Parameters$"),("re","registry_value",r"^(MaxUserPort|TcpTimedWaitDelay)$")],
           [("eq","event_type","PROCESS_LAUNCH"),("re","command_line",r"regedt32(\.exe)?\"?\s+/S\s+.*nmap_performance\.reg")]])],
   ["event_type", "hostname", "registry_key", "registry_value", "command_line"], dict(category="registry_set", **WIN), ["registry_value"]),
 s("ncat_exec_or_broker_grammar", ["hostname", "process_path"], ("#", 1),
   [("eq","event_type","PROCESS_LAUNCH"),("or",[[("re","command_line",NCLONG)],[("re","command_line",NCEXEC),("re","command_line",NCLISTEN),("re","command_line",PORTARG)]])], PCC, PC, ["command_line"]),
 s("ncat_socket_bound_shell_child", ["hostname", "parent_process_path"], ("#", 1),
   [("eq","event_type","PROCESS_LAUNCH"),("re","process_path",SHELL),("re","parent_command_line",BIND),("or",[[("re","parent_command_line",NCLISTEN)],[("re","parent_command_line",IPPORT)]])],
   ["event_type", "hostname", "process_path", "parent_process_path", "parent_command_line"], PC, ["parent_command_line"]),
]

if __name__ == "__main__":
    for sp in nmap:
        print("nmap", sp["name"], render(D / "nmap", sp))
