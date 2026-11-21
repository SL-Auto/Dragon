import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

T = pathlib.Path(__file__).resolve().parents[2] / "detections" / "cobalt-strike-beacon"
WIN = {"product": "windows"}
P = "cobalt_strike_"
S = "_compensating_signal"

specs = [
 dict(name=P+"credential_access_effect"+S, kind="seq", window=5, keys=["hostname", "process_id"],
      columns=["event_type", "hostname", "process_id", "target_process_path", "dangerous_memory_rights", "target_path"],
      legs=[dict(where=[("eq","event_type","PROCESS_OPEN"),("re","target_process_path",r"\\lsass\.exe$"),("eq","dangerous_memory_rights","true")]),
            dict(where=[("eq","event_type","FILE_CREATION"),("re","target_path",r"\.(dmp|mdmp)$")])],
      sigma=dict(category="process_access", **WIN)),
 dict(name=P+"directory_discovery"+S, kind="single", window=30, keys=["user_id", "hostname"], count=("object_class", 4),
      columns=["event_type", "user_id", "hostname", "object_class", "approved_directory_scanner"],
      legs=[dict(where=[("in","event_type",["LDAP_SEARCH","LDAP_QUERY"]),("ne_true","approved_directory_scanner")])],
      sigma=dict(category="ldap_query", **WIN)),
 dict(name=P+"discovery_fanout"+S, kind="single", window=60, keys=["user_id", "hostname"], count=("target_ip", 10),
      note="The canonical rule also requires >=4 distinct ports; SPL/KQL/SQL add that second threshold below the generated one.",
      columns=["event_type", "user_id", "hostname", "target_ip", "target_port", "approved_scanner"],
      legs=[dict(where=[("eq","event_type","NETWORK_CONNECTION"),("ne_true","approved_scanner")])],
      sigma=dict(category="network_connection", **WIN), extra_distinct=("target_port", 4)),
 dict(name=P+"dns_process_context"+S, kind="single", window=30, keys=["hostname", "process_id"], count=("dns_query", 8),
      columns=["event_type", "hostname", "process_id", "dns_query", "dns_type", "domain_baseline_rarity"],
      legs=[dict(where=[("in","event_type",["NETWORK_DNS","DNS_QUERY"]),("or",[[("num","dns_type",16)],[("num","dns_type",10)]]),("eq","domain_baseline_rarity","RARE")])],
      sigma=dict(category="dns_query", **WIN)),
 dict(name=P+"file_cleanup_or_timestomp"+S, kind="seq", window=15, keys=["hostname", "file_path"],
      columns=["event_type", "hostname", "target_process_path", "target_path", "process_signed", "process_prevalence"],
      legs=[dict(where=[("eq","event_type","PROCESS_LAUNCH")], alias={"file_path": "target_process_path"}),
            dict(where=[("in","event_type",["FILE_DELETION","FILE_DELETE"]),("or",[[("false","process_signed")],[("eq","process_prevalence","RARE")]])], alias={"file_path": "target_path"})],
      sigma=dict(category="file_delete", **WIN)),
 dict(name=P+"named_pipe_peer_activity"+S, kind="seq", window=5, keys=["peer_host"],
      columns=["event_type", "hostname", "target_host", "target_port", "pipe_prevalence", "pipe_name"],
      legs=[dict(where=[("eq","event_type","NETWORK_CONNECTION"),("num","target_port",445)], alias={"peer_host": "target_host"}),
            dict(where=[("in","event_type",["NAMED_PIPE_CONNECTION","PIPE_CONNECT"]),("eq","pipe_prevalence","RARE")], alias={"peer_host": "hostname"})],
      sigma=dict(category="pipe_created", **WIN)),
 dict(name=P+"powershell_or_clr_in_unusual_host"+S, kind="single", window=10, keys=[],
      columns=["event_type", "hostname", "target_path", "process_path", "process_signed", "process_prevalence"],
      legs=[dict(where=[("eq","event_type","MODULE_LOAD"),("re","target_path",r"\\(clr|coreclr)\.dll$"),
                        ("or",[[("re","process_path",r"\\(rundll32|dllhost|regsvr32|werfault|searchprotocolhost|gpupdate|spoolsv|notepad|svchost|wuauclt|mstsc)\.exe$")],
                               [("false","process_signed"),("eq","process_prevalence","RARE")]])])],
      sigma=dict(category="image_load", **WIN)),
 dict(name=P+"privileged_context_change"+S, kind="seq", window=10, keys=["hostname", "process_id"],
      columns=["event_type", "hostname", "process_id", "privilege_name", "target_process_path"],
      legs=[dict(where=[("eq","event_type","TOKEN_PRIVILEGE_CHANGE"),("eq","privilege_name","SeDebugPrivilege")]),
            dict(where=[("eq","event_type","PROCESS_OPEN"),("re","target_process_path",r"\\(lsass|winlogon)\.exe$")])],
      sigma=dict(category="process_access", **WIN)),
 dict(name=P+"process_network_context"+S, kind="single", window=120, keys=["process_sha256", "target_host"], count=("#", 8),
      columns=["event_type", "process_sha256", "process_prevalence", "target_host", "interval_variance_bucket", "destination_prevalence"],
      legs=[dict(where=[("eq","event_type","NETWORK_CONNECTION"),("eq","process_prevalence","RARE"),("eq","interval_variance_bucket","LOW"),("eq","destination_prevalence","RARE")])],
      sigma=dict(category="network_connection", **WIN)),
 dict(name=P+"remote_service_sequence"+S, kind="seq", window=10, keys=["service_host", "image_name"],
      columns=["event_type", "product_event_type", "hostname", "target_host", "target_path", "target_process_path"],
      legs=[dict(where=[("in","event_type",["FILE_CREATION","FILE_MODIFICATION","FILE_WRITE"])], alias={"service_host": "target_host"},
                 derive={"image_name": ("target_path", r"([^\\/]+\.(?:exe|dll|bat|cmd|ps1))$")}),
            dict(where=[("eq","product_event_type","7045")], alias={"service_host": "hostname"},
                 derive={"image_name": ("target_process_path", r"([^\\/\"\s]+\.(?:exe|dll|bat|cmd|ps1))")})],
      note="Joined on service host and image file name; the staging source host exists only on the write leg (as in the canonical rule, where $source is bound by the write event).",
      sigma=dict(service="system", **WIN)),
 dict(name=P+"sensitive_file_activity"+S, kind="seq", window=30, keys=["hostname", "user_id"], count=("a", "target_path", 5),
      columns=["event_type", "hostname", "user_id", "target_path", "file_sensitivity"],
      legs=[dict(where=[("eq","event_type","FILE_READ"),("eq","file_sensitivity","HIGH")]),
            dict(where=[("in","event_type",["FILE_CREATION","FILE_MODIFICATION","FILE_WRITE"]),("re","target_path",r"\.(zip|7z|rar)$")])],
      sigma=dict(category="file_event", **WIN)),
 dict(name=P+"sensitive_registry_read"+S, kind="single", window=15, keys=["hostname", "process_sha256"], count=("registry_security_family", 3),
      columns=["event_type", "hostname", "process_sha256", "registry_security_family", "approved_inventory_process"],
      legs=[dict(where=[("eq","event_type","REGISTRY_READ"),("ne_true","approved_inventory_process")])],
      sigma=dict(category="registry_event", **WIN)),
 dict(name=P+"service_or_integrity_transition"+S, kind="single", window=10, keys=[],
      columns=["event_type", "integrity_level", "process_signed", "process_prevalence", "approved_elevation_broker"],
      legs=[dict(where=[("eq","event_type","PROCESS_LAUNCH"),("eq","integrity_level","SYSTEM"),("or",[[("false","process_signed")],[("eq","process_prevalence","RARE")]]),("ne_true","approved_elevation_broker")])],
      sigma=dict(category="process_creation", **WIN)),
 dict(name=P+"socket_fanout_or_forwarding"+S, kind="seq", window=15, keys=["hostname", "relay_process"], count=("b", "target_ip", 5),
      columns=["event_type", "hostname", "direction", "process_id", "target_process_id", "target_ip"],
      legs=[dict(where=[("eq","event_type","NETWORK_CONNECTION"),("eq","direction","INBOUND")], alias={"relay_process": "target_process_id"}),
            dict(where=[("eq","event_type","NETWORK_CONNECTION"),("eq","direction","OUTBOUND")], alias={"relay_process": "process_id"})],
      sigma=dict(category="network_connection", **WIN)),
 dict(name=P+"socket_listen_or_rare_egress"+S, kind="seq", window=30, keys=["hostname", "listen_process", "target_port"],
      columns=["event_type", "hostname", "direction", "process_id", "target_process_id", "target_port", "process_signed", "process_prevalence"],
      legs=[dict(where=[("eq","event_type","SOCKET_LISTEN"),("or",[[("false","process_signed")],[("eq","process_prevalence","RARE")]])], alias={"listen_process": "process_id"}),
            dict(where=[("eq","event_type","NETWORK_CONNECTION"),("eq","direction","INBOUND")], alias={"listen_process": "target_process_id"})],
      sigma=dict(category="network_connection", **WIN)),
 dict(name=P+"suspicious_process_lineage_or_memory"+S, kind="seq", window=5, keys=["hostname", "process_id"],
      columns=["event_type", "hostname", "process_id", "memory_is_private", "memory_has_backing_file", "start_address_in_private_rx", "approved_jit_host"],
      legs=[dict(where=[("eq","event_type","EXECUTABLE_MEMORY"),("eq","memory_is_private","true"),("false","memory_has_backing_file")]),
            dict(where=[("eq","event_type","THREAD_START"),("eq","start_address_in_private_rx","true"),("ne_true","approved_jit_host")])],
      sigma=dict(category="create_remote_thread", **WIN)),
 dict(name=P+"user_data_collection"+S, kind="seq", window=15, keys=["hostname", "process_id"],
      columns=["event_type", "hostname", "process_id", "direction"],
      legs=[dict(where=[("in","event_type",["SCREEN_CAPTURE","CLIPBOARD_READ","INPUT_CAPTURE","BROWSER_SECRET_READ"])]),
            dict(where=[("eq","event_type","NETWORK_CONNECTION"),("eq","direction","OUTBOUND")])],
      sigma=dict(category="network_connection", **WIN)),
]

if __name__ == "__main__":
    import re
    for sp in specs:
        fid = render(T, sp)
        if "extra_distinct" in sp:
            col, n = sp["extra_distinct"]
            for fmt, ext, old, new in [
                ("spl", ".spl", "| where matched_count >= ", f"| eventstats count as _dummy\n| where matched_count >= "),
            ]:
                pass
            # add the second distinct threshold natively to SPL/KQL/SQL
            sp_path = T / "spl" / f"{sp['name']}.spl"; s = sp_path.read_text(encoding="utf-8")
            s = s.replace("| stats dc(target_ip) as matched_count", f"| stats dc(target_ip) as matched_count dc({col}) as distinct_{col}").replace(
                f"| where matched_count >= {sp['count'][1]}", f"| where matched_count >= {sp['count'][1]} AND distinct_{col} >= {n}")
            sp_path.write_text(s, encoding="utf-8", newline="\n")
            k_path = T / "kql" / f"{sp['name']}.kql"; s = k_path.read_text(encoding="utf-8")
            s = s.replace("| summarize MatchedCount = count_distinct(target_ip)", f"| summarize MatchedCount = count_distinct(target_ip), Distinct_{col} = count_distinct({col})").replace(
                f"| where MatchedCount >= {sp['count'][1]}", f"| where MatchedCount >= {sp['count'][1]} and Distinct_{col} >= {n}")
            k_path.write_text(s, encoding="utf-8", newline="\n")
            q_path = T / "sql" / f"{sp['name']}.sql"; s = q_path.read_text(encoding="utf-8")
            s = s.replace(f"HAVING COUNT(DISTINCT target_ip) >= {sp['count'][1]};", f"HAVING COUNT(DISTINCT target_ip) >= {sp['count'][1]}\n   AND COUNT(DISTINCT {col}) >= {n};")
            q_path.write_text(s, encoding="utf-8", newline="\n")
        print(sp["name"], fid)
