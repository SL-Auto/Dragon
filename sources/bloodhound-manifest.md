# BloodHound collector source manifest

Static source only; no project was built or executed.

| Component | Official repository | Pinned revision | Role |
| --- | --- | --- | --- |
| BloodHound CE | https://github.com/SpecterOps/BloodHound | `5e8e78e611bd8a89eb1074053a1ed9b7dc95db38` (`v9.5.1`) | Collector-output schema and ingestion context |
| SharpHound | https://github.com/SpecterOps/SharpHound | `a2f843593a5b55ea645ab466f5c91effeda52dda` | Active Directory collector entry point and orchestration |
| SharpHoundCommon | https://github.com/SpecterOps/SharpHoundCommon | `fcb6cb96accc2b845833a708c2955cd0a2384dfa` | LDAP, RPC, registry, SMB and collection processors used by SharpHound |
| AzureHound | https://github.com/SpecterOps/AzureHound | `23735c8af6b03a677a3c40e8d274316504ea07ab` | Entra ID and Azure Resource Manager collector |

The repositories were cloned through WSL into ignored `sources/*-src/` directories. No release asset, binary, package, malware sample, build command, or collector command was downloaded or executed.
