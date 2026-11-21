"""Native secondary translations for the Pacu CloudTrail and EKS rules.

pacu_iam_credential_backdoor_other_user compares two fields and uses generator candidate retrieval instead
(see reviews/pacu/translation-review.md).
"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from translate_lib import render

D = pathlib.Path(__file__).resolve().parents[2] / "detections"
CT = "AWS CloudTrail"
AWS = dict(category="cloudtrail", product="aws")
CONSOLE = r"(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)"
C = ["product_name", "product_event_type", "principal_arn", "event_source", "source_ip", "user_agent", "resource_name"]


def s(name, count, where, extra=None, values=None, window=30, keys=None):
    return dict(name=name, kind="single", window=window, keys=keys or ["principal_arn"], count=count, values=values or [],
                columns=C + (extra or []), legs=[dict(where=[("eq", "product_name", CT)] + where)], sigma=AWS)


def q(name, first, second, keys=None, extra=None, window=30):
    return dict(name=name, kind="seq", window=window, keys=keys or ["principal_arn"], columns=C + (extra or []),
                legs=[dict(where=[("eq", "product_name", CT)] + first), dict(where=[("eq", "product_name", CT)] + second)], sigma=AWS)


IAMW = ["AttachUserPolicy","AttachRolePolicy","AttachGroupPolicy","PutUserPolicy","PutRolePolicy","PutGroupPolicy","CreatePolicyVersion","SetDefaultPolicyVersion","AddUserToGroup","UpdateAssumeRolePolicy"]
IMPAIR = ["StopLogging","DeleteTrail","UpdateTrail","DeleteDetector","UpdateDetector","CreateIPSet","UpdateIPSet","DeleteConfigurationRecorder","StopConfigurationRecorder","DeleteConfigRule","DeleteFlowLogs","DeleteAlarms","DisableAlarmActions"]

pacu = [
 s("pacu_user_agent_session_suffix", ("#", 1), [("re","user_agent",r"Pacu-Session-[0-9a-fA-F-]{36}")], values=["product_event_type"], window=60),
 s("pacu_iam_privilege_modification_burst", ("product_event_type", 2), [("in","product_event_type",IAMW)]),
 q("pacu_eventbridge_lambda_backdoor_chain", [("re","product_event_type",r"^CreateFunction")], [("eq","product_event_type","PutRule"),("re","event_pattern",r"aws\.(iam|ec2)")], extra=["event_pattern"]),
 s("pacu_cfn_template_bucket_injection", ("#", 1), [("re","product_event_type",r"^PutBucketNotification"),("re","resource_name",r"^cf-templates-")], values=["resource_name"], window=60),
 s("pacu_service_credential_issuance", ("product_event_type", 2), [("in","product_event_type",["CreateKeyPair","ImportKeyPair","GetInstanceAccessDetails","CreateApiKey"]),("re","event_source",r"(lightsail|apigateway)")]),
 s("pacu_security_group_open_ingress", ("resource_name", 3), [("eq","product_event_type","AuthorizeSecurityGroupIngress"),("re","ip_permissions",r"(0\.0\.0\.0/0|::/0)")], extra=["ip_permissions"]),
 q("pacu_ecs_task_definition_run", [("eq","product_event_type","RegisterTaskDefinition")], [("eq","product_event_type","RunTask")]),
 q("pacu_instance_userdata_modify_restart", [("eq","product_event_type","ModifyInstanceAttribute"),("re","request_attribute","userData"),("notre","invoked_by",r"(AWS Internal|\.amazonaws\.com)$")], [("eq","product_event_type","StartInstances")],
   keys=["principal_arn", "resource_name"], extra=["request_attribute", "invoked_by"]),
 s("pacu_detection_service_impairment", ("#", 1), [("in","product_event_type",IMPAIR)], values=["product_event_type", "source_ip"], window=60),
 s("pacu_secret_value_bulk_retrieval", ("resource_name", 5), [("or",[[("in","product_event_type",["GetSecretValue","BatchGetSecretValue"])],
   [("in","product_event_type",["GetParameter","GetParameters","GetParametersByPath"]),("re","with_decryption",r"^true$")]]),("notre","invoked_by",r"(AWS Internal|\.amazonaws\.com)$")],
   extra=["with_decryption", "invoked_by"]),
 q("pacu_ssm_instance_profile_rce_chain", [("in","product_event_type",["AssociateIamInstanceProfile","ReplaceIamInstanceProfileAssociation"])], [("eq","product_event_type","SendCommand")]),
 s("pacu_snapshot_and_database_takeover", ("product_event_type", 2),
   [("or",[[("eq","product_event_type","ModifyDBInstance"),("re","request_parameter_keys","masterUserPassword")],
           [("in","product_event_type",["CreateDBSnapshot","RestoreDBInstanceFromDBSnapshot","CreateVolume","AttachVolume","ListSnapshotBlocks","GetSnapshotBlock"])]])],
   extra=["request_parameter_keys"]),
 s("pacu_s3_bulk_object_download", ("resource_name", 100), [("eq","product_event_type","GetObject")]),
 s("pacu_access_denied_permission_bruteforce", ("product_event_type", 10), [("re","error_code",r"(AccessDenied|UnauthorizedOperation)")], extra=["error_code"], window=10),
 s("pacu_log_formula_injection", ("#", 1), [("in","product_event_type",["CreateTrail","RunInstances"]),("re","request_name",r"^\s*[=+@]|^\s*-[^-\s]")], extra=["request_name"], values=["request_name"], window=60),
 s("pacu_organization_member_role_assumption", ("account_id", 2), [("eq","product_event_type","AssumeRole"),("re","resource_name",r":role/OrganizationAccountAccessRole$")], extra=["account_id"], window=60),
 s("pacu_multi_service_enumeration_fanout", ("event_source", 15), [("re","product_event_type",r"^(List|Describe|Get)[A-Z]"),("notre","user_agent",CONSOLE)]),
 s("pacu_sns_topic_subscription_fanout", ("resource_name", 3), [("eq","product_event_type","Subscribe")]),
 q("pacu_credential_report_generation", [("eq","product_event_type","GenerateCredentialReport"),("notre","user_agent",r"(console\.amazonaws\.com|AWS Internal)")], [("eq","product_event_type","GetCredentialReport")]),
 dict(name="pacu_eks_service_account_token_collection", kind="single", window=30, keys=["user_id"], count=("namespace", 3), values=[],
      columns=["product_event_type", "user_id", "namespace"], legs=[dict(where=[("re","product_event_type",r"(get|list|watch|create).*(secrets|serviceaccounts/token)")])],
      sigma=dict(category="eks_audit", product="aws")),
 s("pacu_cognito_pool_abuse", ("product_event_type", 2), [("in","product_event_type",["CreateUserPool","CreateUserPoolClient","CreateIdentityPool","AdminCreateUser","AdminUpdateUserAttributes"])]),
]

if __name__ == "__main__":
    for sp in pacu:
        print("pacu", sp["name"], render(D / "pacu", sp))
