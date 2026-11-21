"""Native secondary translations for single-event ROADtools rules.

The four multi-event rules (device-to-PRT, device-to-key, Seamless SSO correlation and the absence-based
SAML rule) use generator candidate retrieval; see reviews/roadtools/translation-review.md.
"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

D = pathlib.Path(__file__).resolve().parents[2] / "detections"
AZ = dict(category="azure_signin", product="azure")
SL = ["SigninLogs", "AADNonInteractiveUserSignInLogs"]
C = ["product_event_type", "user_id", "source_ip", "user_agent", "app_id", "resource_id", "auth_protocol", "incoming_token_type", "result_type"]


def s(name, keys, count, where, extra=None, values=None, window=60, sigma=AZ):
    return dict(name=name, kind="single", window=window, keys=keys, count=count, values=values or [], columns=C + (extra or []), legs=[dict(where=where)], sigma=sigma)


road = [
 s("roadtools_device_code_or_ropc_signin", ["user_id"], ("#", 1), [("in","product_event_type",SL),("re","auth_protocol",r"^(deviceCode|ropc)$"),("eq","result_type","0")], values=["auth_protocol", "app_id"]),
 s("roadtools_foci_refresh_token_client_hopping", ["user_id", "source_ip"], ("app_id", 4), [("eq","product_event_type","AADNonInteractiveUserSignInLogs"),("re","incoming_token_type","refreshToken"),("eq","result_type","0")], window=30),
 s("roadtools_scripting_user_agent_signin", ["user_id"], ("#", 1), [("in","product_event_type",SL + ["AADServicePrincipalSignInLogs","MicrosoftGraphActivityLogs"]),("re","user_agent",r"(python-requests/|aiohttp/|Python/[0-9.]+ aiohttp)")], values=["product_event_type"]),
 s("roadtools_prt_cookie_legacy_user_agent", ["user_id"], ("#", 1), [("re","user_agent",r"MSIE 7\.0; Windows NT 10\.0; Win64; x64; Trident/7\.0; \.NET4\.0C; \.NET4\.0E")], values=["source_ip"]),
 s("roadtools_registered_device_default_name", ["user_id"], ("#", 1), [("in","product_event_type",["Register device","Add device"]),("re","device_name",r"^DESKTOP-[A-Z0-9]{7}$"),("notre","initiated_by_app",r"(intune|autopilot|device management)")],
   extra=["device_name", "initiated_by_app"], values=["device_name"], sigma=dict(category="azure_audit", product="azure")),
 s("roadtools_passkey_default_name_registration", ["target_user"], ("#", 1), [("re","product_event_type",r"(passkey|FIDO2|security info|security key)"),("re","modified_properties",r"\broadtx\b")],
   extra=["target_user", "modified_properties"], sigma=dict(category="azure_audit", product="azure")),
 s("roadtools_aad_graph_resource_token", ["user_id"], ("#", 1), [("in","product_event_type",SL),("eq","resource_id","00000002-0000-0000-c000-000000000000"),("eq","result_type","0")], values=["app_id"]),
 s("roadtools_graph_directory_bulk_read", ["user_id"], ("#", 500), [("eq","product_event_type","MicrosoftGraphActivityLogs"),("re","request_uri",r"/(v1\.0|beta)/(users|groups|devices|applications|servicePrincipals|directoryRoles|roleManagement|policies)")],
   extra=["request_uri"], window=10, sigma=dict(category="azure_graph", product="azure")),
 dict(name="roadtools_browsercore_native_host_hijack", kind="single", window=60, keys=["hostname"], count=("#", 1), values=["target_path", "registry_key"],
      columns=["event_type", "hostname", "registry_key", "registry_value_data", "target_path"],
      legs=[dict(where=[("or",[[("eq","event_type","REGISTRY_MODIFICATION"),("re","registry_key",r"\NativeMessagingHosts\com\.microsoft\.browsercore"),("notre","registry_value_data",r"\Windows\BrowserCore\manifest\.json")],
                              [("eq","event_type","FILE_CREATION"),("re","target_path",r"\BrowserCore\.py$")]])])],
      sigma=dict(category="registry_set", product="windows")),
 s("roadtools_federated_credential_sp_signin", ["user_id"], ("#", 1), [("eq","product_event_type","AADServicePrincipalSignInLogs"),("re","client_credential_type","federatedIdentityCredential"),
   ("notre","federated_issuer",r"(token\.actions\.githubusercontent\.com|sts\.windows\.net|login\.microsoftonline\.com|accounts\.google\.com|oidc\.eks\.|gitlab\.com)")], extra=["client_credential_type", "federated_issuer"], values=["federated_issuer"]),
 s("roadtools_aad_graph_internal_api_version", ["user_id"], ("#", 1), [("eq","product_event_type","AADGraphActivityLogs"),("re","api_version",r"^1\.61?-internal$")], extra=["api_version"], values=["user_agent"], sigma=dict(category="azure_aadgraph", product="azure")),
 s("roadtools_broker_client_device_code_signin", ["user_id"], ("#", 1), [("in","product_event_type",SL),("re","auth_protocol",r"^deviceCode$"),("eq","app_id","29d9ed98-a469-4536-ade2-f981bc1d605e"),("eq","result_type","0")], values=["source_ip"]),
 dict(name="roadtools_hello_assertion_script", kind="single", window=60, keys=["hostname"], count=("#", 1), values=["user_id"],
      columns=["product_event_type", "hostname", "user_id", "script_block_text"],
      legs=[dict(where=[("eq","product_event_type","4104"),("re","script_block_text",r"(WebAuthNAuthenticatorGetAssertion|webauthn\.dll|Microsoft Passport Key Storage Provider|NCryptSignHash)")])],
      sigma=dict(category="ps_script", product="windows")),
]

if __name__ == "__main__":
    for sp in road:
        print("roadtools", sp["name"], render(D / "roadtools", sp))
