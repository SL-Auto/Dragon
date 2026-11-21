"""Native secondary translations for single-event ScoutSuite rules.

scoutsuite_aws_userdata_and_credential_report_sweep (unordered two-event join with a per-leg count) uses
generator candidate retrieval; see reviews/scoutsuite/translation-review.md.
"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

D = pathlib.Path(__file__).resolve().parents[2] / "detections"


def s(name, keys, count, where, cols, sigma, values=None, window=30):
    return dict(name=name, kind="single", window=window, keys=keys, count=count, values=values or [], columns=cols, legs=[dict(where=where)], sigma=sigma)


scout = [
 s("scoutsuite_user_agent_in_cloud_audit", ["principal_id"], ("#", 1), [("re","user_agent",r"Scout ?Suite/[0-9]")],
   ["principal_id", "user_agent", "event_source", "source_ip"], dict(category="cloud_audit"), ["event_source"], window=60),
 s("scoutsuite_aws_multi_service_read_fanout", ["principal_arn"], ("event_source", 20),
   [("re","product_event_type",r"^(List|Describe|Get)[A-Z]"),("notre","user_agent",r"(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)")],
   ["product_event_type", "principal_arn", "event_source", "user_agent"], dict(category="cloudtrail", product="aws")),
 s("scoutsuite_gcp_multi_service_read_fanout", ["principal_email"], ("service_name", 10),
   [("re","product_event_type",r"\.(List|Get|Search|Aggregated|GetIamPolicy)[A-Za-z]*$|\.(list|get|search|aggregatedList|getIamPolicy)$")],
   ["product_event_type", "principal_email", "service_name"], dict(category="gcp_audit", product="gcp")),
 s("scoutsuite_azure_arm_read_fanout", ["caller"], ("resource_provider", 8), [("eq","product_event_type","AZURE_RESOURCE_READ")],
   ["product_event_type", "caller", "resource_provider"], dict(category="azure_activity", product="azure")),
 s("scoutsuite_kubernetes_cluster_wide_secret_and_resource_list", ["user_id"], ("resource", 11), [("re","product_event_type",r"^list")],
   ["product_event_type", "user_id", "resource"], dict(category="k8s_audit"), window=10),
 s("scoutsuite_cli_execution", ["hostname", "process_path"], ("#", 1),
   [("eq","event_type","PROCESS_LAUNCH"),("re","command_line",r"((^|[\s\\/\"])scout(\.exe|\.py)?\"?\s+(aws|azure|gcp|aliyun|oci|do|kubernetes)(\s|$)|-m\s+ScoutSuite(\s|$))")],
   ["event_type", "hostname", "process_path", "command_line"], dict(category="process_creation", product="windows"), ["command_line"], window=60),
]

if __name__ == "__main__":
    for sp in scout:
        print("scoutsuite", sp["name"], render(D / "scoutsuite", sp))
