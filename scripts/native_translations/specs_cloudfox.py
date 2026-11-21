"""Native secondary translations for the 13 CloudFox cloud-audit rules (all single-event aggregations)."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

D = pathlib.Path(__file__).resolve().parents[2] / "detections"
CT = "AWS CloudTrail"
CONSOLE = r"(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)"
AWS = dict(category="cloudtrail", product="aws")
AZ = dict(category="azure_activity", product="azure")
GCP = dict(category="gcp_audit", product="gcp")
MODULES = (r"(^|\s)(aws\s+(all-checks|access-keys|api-gw|env-vars|filesystems|iam-simulator|ecs-tasks|elastic-network-interfaces|network-ports|outbound-assumed-roles|principals|resource-trusts|role-trusts|workloads|cape|pmapper)"
           r"|azure\s+(whoami|tokencache|rbac|automation)|gcp\s+(all-checks|hiddenadmins|privesc|lateralmovement|dataexfiltration|foxmapper|bucketenum|logenum|bigqueryenum|domainwidedelegation|workloadidentity))(\s|$)")
CTC = ["product_name", "product_event_type", "principal_arn", "event_source", "source_ip", "user_agent"]


def s(name, keys, count, where, cols, sigma, values=None, window=30):
    return dict(name=name, kind="single", window=window, keys=keys, count=count, values=values or [],
                columns=cols, legs=[dict(where=where)], sigma=sigma)


cloudfox = [
 s("cloudfox_aws_multi_service_enumeration_fanout", ["principal_arn"], ("event_source", 15),
   [("eq","product_name",CT),("re","product_event_type",r"^(List|Describe|Get)[A-Z]"),("notre","user_agent",CONSOLE)], CTC, AWS, ["source_ip", "user_agent"]),
 s("cloudfox_aws_instance_userdata_bulk_read", ["principal_arn"], ("resource_name", 3),
   [("eq","product_name",CT),("eq","product_event_type","DescribeInstanceAttribute"),("re","request_attribute",r"^userData$"),
    ("notre","invoked_by",r"(AWS Internal|\.amazonaws\.com)$")],
   CTC + ["request_attribute", "resource_name", "invoked_by"], AWS, ["source_ip"]),
 s("cloudfox_aws_secret_bearing_config_sweep", ["principal_arn"], ("product_event_type", 3),
   [("eq","product_name",CT),("in","product_event_type",["DescribeInstanceAttribute","DescribeTaskDefinition","BatchGetProjects","GetTemplate","ListFunctions","GetFunctionConfiguration"]),
    ("notre","user_agent",CONSOLE)], CTC, AWS),
 s("cloudfox_aws_policy_simulation_fanout", ["principal_arn"], ("resource_name", 3),
   [("eq","product_name",CT),("eq","product_event_type","SimulatePrincipalPolicy")], CTC + ["resource_name"], AWS),
 s("cloudfox_aws_authorization_details_dump", ["principal_arn"], ("#", 1),
   [("eq","product_name",CT),("eq","product_event_type","GetAccountAuthorizationDetails")], CTC, AWS, ["source_ip"], window=60),
 s("cloudfox_aws_programmatic_assumerole_history_lookup", ["principal_arn"], ("#", 1),
   [("eq","product_name",CT),("eq","product_event_type","LookupEvents"),("re","lookup_attributes","AssumeRole"),("notre","user_agent",CONSOLE)],
   CTC + ["lookup_attributes"], AWS, ["user_agent"], window=60),
 s("cloudfox_azure_app_settings_secret_list", ["caller"], ("resource_name", 2),
   [("re","product_event_type",r"^MICROSOFT\.WEB/SITES/(SLOTS/)?CONFIG/LIST/ACTION$")], ["product_event_type", "caller", "resource_name", "source_ip"], AZ, ["source_ip"]),
 s("cloudfox_azure_arm_read_fanout", ["caller"], ("resource_provider", 5),
   [("eq","product_event_type","AZURE_RESOURCE_READ")], ["product_event_type", "caller", "resource_provider"], AZ),
 s("cloudfox_azure_storage_listing_fanout", ["requester"], ("resource_name", 3),
   [("in","product_event_type",["ListContainers","ListBlobs"])], ["product_event_type", "requester", "resource_name"], dict(category="azure_storage", product="azure")),
 s("cloudfox_gcp_bigquery_select_star_sampling", ["principal_email"], ("query", 2),
   [("re","product_event_type",r"(jobservice\.insert|JobService\.InsertJob|jobs\.insert)"),
    ("re","query",r"^\s*SELECT\s+\*\s+FROM\s+`[^`]+\.[^`]+\.[^`]+`\s+LIMIT\s+\d+\s*$")], ["product_event_type", "principal_email", "query"], GCP),
 s("cloudfox_gcp_iam_policy_read_fanout", ["principal_email"], ("resource_name", 10),
   [("re","product_event_type",r"GetIamPolicy$")], ["product_event_type", "principal_email", "resource_name", "service_name"], GCP, ["service_name"]),
 s("cloudfox_gcp_content_listing_fanout", ["principal_email"], ("resource_name", 5),
   [("re","product_event_type",r"(storage\.objects\.list|ListLogEntries)$")], ["product_event_type", "principal_email", "resource_name"], GCP),
 s("cloudfox_gcp_multi_service_inventory", ["principal_email"], ("service_name", 10),
   [("re","product_event_type",r"\.(List|Get|Search|Aggregated)[A-Za-z]*$|\.(list|get|search|aggregatedList)$")],
   ["product_event_type", "principal_email", "service_name"], GCP),
 # Added after public comparison (CF-DR-11, CF-DR-12).
 s("cloudfox_gcp_secret_metadata_multi_project", ["principal_email"], ("project_id", 5),
   [("re","product_event_type",r"SecretManagerService\.ListSecrets$")], ["product_event_type", "principal_email", "project_id"], GCP),
 s("cloudfox_cli_module_grammar_execution", ["hostname", "process_path"], ("#", 1),
   [("eq","event_type","PROCESS_LAUNCH"),("re","command_line",MODULES)], ["event_type", "hostname", "process_path", "command_line"],
   dict(category="process_creation", product="windows"), ["command_line"], window=60),
]

if __name__ == "__main__":
    for sp in cloudfox:
        print("cloudfox", sp["name"], render(D / "cloudfox", sp))
