import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

D = pathlib.Path(__file__).resolve().parents[2] / "detections"
WIN = {"product": "windows"}

rubeus = [
 dict(name="rubeus_lsa_encoded_ticket_retrieval", kind="single", window=10, keys=["hostname", "process_id"], count=("#", 1), values=["target_luid", "process_path"],
      columns=["product_event_type", "hostname", "process_id", "process_path", "api_name", "kerberos_message_type", "result", "target_luid"],
      legs=[dict(where=[("eq","product_event_type","EDR_API_CALL"),("eq","api_name","LsaCallAuthenticationPackage"),("re","kerberos_message_type",r"^Kerb(RetrieveEncodedTicket|RetrieveTicket)(Message)?$"),("eq","result","ALLOW")])],
      sigma=dict(category="api_call", **WIN)),
 dict(name="rubeus_lsa_ticket_submission", kind="single", window=10, keys=["hostname", "process_id"], count=("#", 1), values=["target_luid", "process_path"],
      columns=["product_event_type", "hostname", "process_id", "process_path", "api_name", "kerberos_message_type", "result", "target_luid"],
      legs=[dict(where=[("eq","product_event_type","EDR_API_CALL"),("eq","api_name","LsaCallAuthenticationPackage"),("re","kerberos_message_type",r"^KerbSubmitTicket(Message)?$"),("eq","result","ALLOW")])],
      sigma=dict(category="api_call", **WIN)),
 dict(name="rubeus_rc4_service_ticket_fanout", kind="single", window=15, keys=["source_ip", "user_id"], count=("service_name", 3),
      columns=["product_event_type", "source_ip", "user_id", "service_name", "TicketEncryptionType", "Status", "approved_legacy_rc4_service"],
      legs=[dict(where=[("eq","product_event_type","4769"),("eq","TicketEncryptionType","0x17"),("eq","Status","0x0"),("ne_true","approved_legacy_rc4_service"),("notre","service_name",r"(\$$|^krbtgt$)")])],
      sigma=dict(service="security", **WIN)),
 dict(name="rubeus_ticket_renewal_anomaly", kind="single", window=10, keys=["source_ip", "user_id"], count=("#", 15), values=["service_name"],
      columns=["product_event_type", "source_ip", "user_id", "service_name"],
      legs=[dict(where=[("eq","product_event_type","4770")])],
      sigma=dict(service="security", **WIN)),
 # Added 2026-11-21 (REVIEW-012, REVIEW-014, REVIEW-015).
 dict(name="rubeus_as_request_failed_preauth_fanout", kind="single", window=10, keys=["source_ip"], count=("user_id", 3),
      columns=["product_event_type", "source_ip", "user_id", "Status", "action"],
      legs=[dict(where=[("in","product_event_type",["4768","4771"]),("or",[[("eq","action","BLOCK")],[("re","Status",r"^0x(6|12|18)$")]])])],
      sigma=dict(service="security", **WIN)),
 dict(name="rubeus_asrep_single_account_sensitive", kind="single", window=60, keys=["source_ip", "user_id"], count=("#", 1), values=["TicketEncryptionType"],
      columns=["product_event_type", "source_ip", "user_id", "PreAuthType", "Status", "account_risk_tier", "TicketEncryptionType"],
      legs=[dict(where=[("eq","product_event_type","4768"),("eq","PreAuthType","0"),("eq","Status","0x0"),("eq","account_risk_tier","high")])],
      sigma=dict(service="security", **WIN)),
 dict(name="rubeus_kerberos_transport_from_unexpected_process", kind="single", window=10, keys=["hostname", "process_path"], count=("#", 1), values=["target_port", "target_ip", "user_id"],
      columns=["event_type", "hostname", "process_path", "target_ip", "target_port", "user_id"],
      legs=[dict(where=[("eq","event_type","NETWORK_CONNECTION"),("or",[[("num","target_port",88)],[("num","target_port",464)]]),("re","process_path",r"^[a-z]:\\"),("notre","process_path",r"^[a-z]:\\windows\\system32\\lsass\.exe$")])],
      sigma=dict(category="network_connection", **WIN)),
]
impacket = [
 dict(name="impacket_ntlm_relay_with_privileged_effect", kind="seq", window=5, keys=["target_host", "acting_user"],
      columns=["product_event_type", "hostname", "target_host", "user_id", "target_user", "LogonType", "AuthenticationPackageName", "source_ip"],
      legs=[dict(where=[("eq","product_event_type","4624"),("eq","LogonType","3"),("re","AuthenticationPackageName",r"^NTLM$")], alias={"acting_user": "target_user"}),
            dict(where=[("in","product_event_type",["4697","7045","4720","4722","4723","4724","4725","4726","4738","4741","4742","4743","4728","4729","4732","4733","4756","4757","5136","5137"])], alias={"acting_user": "user_id"})],
      sigma=dict(service="security", **WIN)),
 dict(name="impacket_terminal_services_session_control_by_other_actor", kind="single", window=10, keys=["hostname"], count=("#", 1), values=["user_id", "target_user"],
      note="The canonical field-to-field inequality (acting user differs from session owner) is expressed natively in SPL/KQL/SQL below; Sigma cannot compare two fields and EQL cannot aggregate.",
      columns=["product_event_type", "hostname", "user_id", "target_user"],
      legs=[dict(where=[("in","product_event_type",["4778","4779","23","24","25"])])],
      sigma=dict(service="terminalservices-localsessionmanager", **WIN), field_ne=("user_id", "target_user")),
 dict(name="impacket_wmi_activity_operational_class_signal", kind="single", window=10, keys=["hostname"], count=("#", 1), values=["source_ip", "product_event_type"],
      columns=["product_event_type", "hostname", "source_ip", "wmi_class"],
      legs=[dict(where=[("in","product_event_type",["5857","5858","5860","5861"]),("re","wmi_class","Win32_Process")])],
      sigma=dict(service="wmi", **WIN)),
 # Added 2026-11-21 (REVIEW-013, REVIEW-014).
 dict(name="impacket_directory_replication_rights_use", kind="single", window=10, keys=["user_id"], count=("#", 1), values=["hostname"],
      columns=["product_event_type", "hostname", "user_id", "properties", "approved_replication_principal"],
      legs=[dict(where=[("eq","product_event_type","4662"),("re","properties",r"(DS-Replication-Get-Changes|Replicating Directory Changes|1131f6a[a-d]-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c)"),("ne_true","approved_replication_principal")])],
      sigma=dict(service="security", **WIN)),
 dict(name="impacket_new_machine_account_s4u", kind="seq", window=60, keys=["target_user"],
      columns=["product_event_type", "user_id", "target_user", "service_name", "source_ip", "description", "delegation_flow", "TransmittedServices"],
      legs=[dict(where=[("eq","product_event_type","4741")]),
            dict(where=[("eq","product_event_type","4769"),("or",[[("re","description",r"(S4U2Self|S4U2Proxy|protocol transition|transited services)")],[("re","delegation_flow",r"^(S4U2Self|S4U2Proxy)$")],[("re","TransmittedServices",r"[A-Za-z0-9]")]])])],
      sigma=dict(service="security", **WIN)),
]

if __name__ == "__main__":
    for tool, specs in (("rubeus", rubeus), ("impacket", impacket)):
        for sp in specs:
            fid = render(D / tool, sp)
            if "field_ne" in sp:
                a, b = sp["field_ne"]
                t = D / tool
                for fmt, ext, old, new in (
                    ("spl", ".spl", "| where in(product_event_type", f"| where isnotnull({a}) AND isnotnull({b}) AND {a}!={b}\n| where in(product_event_type"),
                    ("kql", ".kql", "| where product_event_type in", f"| where isnotempty({a}) and isnotempty({b}) and {a} != {b}\n| where product_event_type in"),
                    ("sql", ".sql", "  AND product_event_type IN", f"  AND {a} IS NOT NULL AND {b} IS NOT NULL AND {a} <> {b}\n  AND product_event_type IN"),
                    ("eql", ".eql", "any where ", f"any where {a.replace('user_id','user.id')} != null and labels.{b} != null and {a.replace('user_id','user.id')} != labels.{b} and ")):
                    p = t / fmt / f"{sp['name']}{ext}"; s = p.read_text(encoding="utf-8")
                    assert old in s, (fmt, old); p.write_text(s.replace(old, new, 1), encoding="utf-8", newline="\n")
                # Sigma cannot express the inequality: mark partial
                p = t / "sigma" / f"{sp['name']}.yml"; s = p.read_text(encoding="utf-8")
                p.write_text(s.replace("fidelity: high", "fidelity: partial", 1), encoding="utf-8", newline="\n")
                fid["sigma"] = "partial"
            print(tool, sp["name"], fid)
