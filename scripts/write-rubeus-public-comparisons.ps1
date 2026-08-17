$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outRoot = Join-Path $repoRoot 'public-rules/comparisons/rubeus'
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null
$elastic = 'public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef'
$sentinel = 'public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728'

$specs = @(
@{n='rubeus_as_request_anomaly'; p='PROC-001'; pub=@("$elastic/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml"); branches=@(
@('AS request reaches a KDC','4768 fan-out by source across three accounts','Port 88 flow followed by authentication from a nonstandard process','4768 account/source cardinality - moderate','Process-attributed KDC network flow - moderate','complementary','Ours covers multi-principal probing; public adds process/network context.'),
@('Atypical preauthentication or failed probing','Not distinguished beyond 4768 count','Authentication result is present but public sequence is not AS-specific','4768 result and PreAuthType - moderate','4768 failure/result baselines','ours_stronger','Public rule does not isolate AS request failure/preauthentication branches.'),
@('Single-account TGT acquisition','Below three-account threshold','Can detect an unusual process making a KDC request','Process-to-KDC flow - moderate','Rare-process and account baseline','public_stronger','Ours deliberately misses a single targeted request.') ); missO='Single-account requests; repeated requests spread across source IPs; account-specific preauthentication anomalies.'; missP='AS-specific request/result semantics and multi-principal probing.'; missB='Encrypted or un-attributed KDC traffic when neither DC 4768 nor endpoint network attribution is complete.'; edge='NAT can merge independent clients; DHCP and IPv6 representations can split one source. Password audits and identity infrastructure create benign fan-out. Source-only cardinality does not model account sensitivity or per-account history.'; signals=@(@('4768 across distinct principals','moderate','ours','Behavioral fan-out but common in scanners and identity systems.'),@('Unusual process contacting KDC','moderate','public','Adds endpoint context but process rarity is environment-dependent.'),@('Single 4768','weak','both','Normal authentication is overwhelmingly common.')); pubWeak='Broad Kerberos network/authentication sequence is not AS-specific and can conflate normal ticket activity.'; ourWeak='The condition does not implement the advertised atypical PreAuthType or result branches; it is only a three-account source fan-out.'; decision='Add separate 4768 branches for failure/preauthentication anomalies and sensitive-account baselines; keep process-to-KDC context as a compensating signal, subject to independent telemetry verification.'},
@{n='rubeus_asrep_roast_sequence'; p='PROC-003'; pub=@("$elastic/rules/windows/credential_access_disable_kerberos_preauth.toml","$elastic/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml"); branches=@(
@('Account becomes roastable','Not covered','Public rule detects disabling Kerberos preauthentication','Directory account-control change - strong','Change actor and approved-change context','public_stronger','Public covers the enabling configuration change, which is causally prior to roasting.'),
@('No-preauthentication AS response requested','4768 PreAuthType 0 for three accounts from one source','Only broad KDC traffic/authentication context','4768 PreAuthType 0 - strong','Endpoint process-to-KDC flow','ours_stronger','Ours directly observes the no-preauthentication request branch.'),
@('AS-REP collection against one account','Below threshold','Broad unusual-process flow may alert','Process-attributed KDC flow - moderate','Sensitive-account and first-seen baselines','public_stronger','Public compensating signal can cover a single request where ours requires three accounts.') ); missO='Single-account roasting; requests distributed across sources or beyond ten minutes; parser variants where PreAuthType is numeric.'; missP='Direct no-preauthentication request semantics and AS-REP fan-out.'; missB='Offline cracking after response collection has no distinctive standard log.'; edge='PreAuthType representation varies by collector. NAT can aggregate sources. Existing accounts without preauthentication produce no configuration-change event during the detection window.'; signals=@(@('4768 with PreAuthType 0','strong','ours','Close to the roastable AS exchange and relatively uncommon.'),@('Preauthentication disabled','strong','public','Security-relevant enabling state change, though not proof of exploitation.'),@('Unusual process to port 88','moderate','public','Useful compensation but not AS-REP specific.')); pubWeak='The configuration rule cannot show exploitation of accounts already configured without preauthentication; the network rule is broad.'; ourWeak='The three-account threshold creates a material targeted-single-account gap and assumes one stable source.'; decision='Retain the strong PreAuthType branch; add a lower-volume sensitive/rare-account branch and separately monitor preauthentication-disable changes after verifying directory audit mappings.'},
@{n='rubeus_kerberoast_sequence'; p='PROC-004'; pub=@("$sentinel/Detections/SecurityEvent/PotentialKerberoast.yaml","$sentinel/Solutions/Microsoft Defender XDR/Analytic Rules/Execution/PotentialKerberoastActivities.yaml","$elastic/rules/windows/credential_access_kerberoasting_unusual_process.toml"); branches=@(
@('SPN-bearing accounts discovered','LDAP filter for servicePrincipalName','Not required by public rules','LDAP SPN search - moderate','Directory query fan-out and caller context','ours_stronger','Ours captures reconnaissance immediately preceding requests.'),
@('Roastable service tickets requested','Five services after LDAP search','Sentinel detects RC4/options burst; MDE uses Kerberoast-tagged identity events; Elastic uses unusual process Kerberos traffic','4769 RC4/options plus service fan-out - strong','Unusual process-to-KDC flow','complementary','Public rules cover ticket properties and single-stage activity; ours adds ordered reconnaissance.'),
@('Single high-value SPN requested','Below five-service threshold','RC4/options or MDE enriched event may detect','Rare RC4 request for sensitive SPN - strong','First-seen requester-to-SPN relationship','public_stronger','Public ticket-property branches cover targeted low volume better.') ); missO='Targeted single-SPN requests; roasting without visible LDAP; distributed or slow fan-out; encryption/ticket-option risk.'; missP='LDAP-to-TGS ordered sequence and non-RC4 roastable tickets.'; missB='Offline cracking and credential use without later correlated authentication.'; edge='Legitimate service discovery produces the same LDAP filter. Modern AES-capable service accounts reduce RC4 usefulness. Host/user joins can fail when DC events lack hostname or use different identity forms.'; signals=@(@('4769 RC4 with roast-associated options','strong','public','Close to a roastable ticket request and more specific than volume alone.'),@('LDAP SPN search followed by TGS fan-out','strong','ours','Ordered procedure coverage, dependent on rare LDAP telemetry.'),@('Unusual process using Kerberos','moderate','public','Broad but useful when DC fields are incomplete.')); pubWeak='RC4-only logic misses AES requests and may rely on fragile option constants; MDE technique tags are opaque upstream enrichment.'; ourWeak='Requires LDAP visibility and five services, omits ticket encryption/options, and can miss targeted or tool-separated activity.'; decision='Improve ours with an independent 4769 RC4/rare-SPN branch and allow the LDAP sequence to remain a high-confidence branch; do not copy fixed public thresholds without tenant evidence.'},
@{n='rubeus_kerberos_over_http_proxy'; p='PROC-013'; pub=@("$elastic/rules/windows/credential_access_kerberoasting_unusual_process.toml"); branches=@(
@('Kerberos payload sent through HTTP proxy','HTTP event with application/kerberos','Public rule observes direct Kerberos traffic from unusual processes, not HTTP transport','Kerberos HTTP content type - strong','Proxy destination plus initiating process','ours_stronger','Ours covers the alternate transport directly.'),
@('Unapproved process initiates request','Description claims unusual process but condition does not test process','Public rule has extensive process allow/deny context for direct KDC traffic','Process attribution and signer - moderate','Approved KDC-proxy client inventory','public_stronger','Our implementation omits its stated unapproved-process branch.'),
@('Approved KDC proxy use','Alerts on every matching content type','Public direct-Kerberos rule is out of scope','Approved-client/destination baseline - moderate','TLS proxy and endpoint process correlation','insufficient_evidence','Neither rule provides a safe KDC-proxy-specific allow model.') ); missO='Process identity, proxy destination, approved-client baseline, URI/method consistency, and TLS visibility limitations.'; missP='Kerberos-over-HTTP itself.'; missB='Encrypted HTTP where content type is unavailable and endpoint network telemetry lacks process attribution.'; edge='Content-Type casing/parameters and proxy normalization vary. Approved remote-access clients may generate identical traffic. Network-only records may not identify the initiating process.'; signals=@(@('application/kerberos content type','strong','ours','Protocol-specific, but only when visible.'),@('Unusual process context','moderate','public','Useful attribution; mutable and environment-dependent.'),@('HTTP destination alone','weak','neither','Proxy endpoints can be shared and legitimate.')); pubWeak='Direct port-88/process logic does not cover HTTP KDC proxy transport.'; ourWeak='The rule description promises an unapproved-process test that the event condition does not implement, creating high benign volume and weak attribution.'; decision='Fix ours by correlating content type with process identity, signer and approved proxy destinations; preserve a content-type-only lower-severity branch when process attribution is absent.'},
@{n='rubeus_lsa_ticket_cache_operations'; p='PROC-006'; pub=@("$elastic/rules/windows/credential_access_posh_kerb_ticket_dump.toml"); branches=@(
@('Ticket cache enumerated','EDR LsaCallAuthenticationPackage plus query message','PowerShell script content names the same API/message families','Kerberos authentication-package message - strong','PowerShell 4104 content','complementary','Both cover the causal API; ours is process-language independent, public covers script telemetry.'),
@('Encoded ticket retrieved','EDR retrieve message','PowerShell rule includes retrieve/decrypt message constants','RetrieveEncodedTicket API - strong','File creation or later ticket use','equivalent','Both directly represent retrieval when their respective telemetry exists.'),
@('Monitoring/harvesting over time','Single API event only','Single script-content event only','Repeated API calls across LUIDs - strong','Subsequent ticket artifact creation','different_scope','Neither rule models periodic harvesting or breadth across sessions.') ); missO='Repeated monitoring, number of LUIDs/tickets, caller signer/path, target-session sensitivity, direct memory access.'; missP='Non-PowerShell implementations and API activity without script logging.'; missB='Offline cache parsing and sensors that do not expose authentication-package calls.'; edge='Klist, SSO, EDR and IR tools legitimately call these APIs. One API call does not distinguish query from bulk extraction impact without message and result detail.'; signals=@(@('RetrieveEncodedTicket message','strong','both','Direct causal operation for ticket retrieval.'),@('QueryTicketCache message','moderate','both','Can be benign enumeration.'),@('PowerShell literal strings','moderate','public','Specific but language/telemetry constrained.')); pubWeak='PowerShell-only visibility leaves compiled/native paths uncovered and script content may be absent.'; ourWeak='Treats one query like bulk extraction and does not use caller trust, result, ticket count, target LUID or repetition.'; decision='Split query from retrieval severity; add caller trust and cross-LUID/repetition branches. Use PowerShell content only as a complementary implementation-specific signal.'},
@{n='rubeus_lsa_ticket_mutation'; p='PROC-007'; pub=@("$elastic/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml"); branches=@(
@('Ticket submitted to LSA','Direct KerbSubmitTicketMessage API','Public rule observes later Kerberos network/authentication sequence','Ticket-submit API - strong','Resource-side Kerberos use','ours_stronger','Ours is closest to the mutation operation.'),
@('Ticket cache purged','Direct purge API','No direct public branch','Purge API plus caller - moderate','Abrupt cache-state change or reauthentication','ours_stronger','Public corpus has no equivalent purge operation.'),
@('Submitted ticket used','Not required','Public network/authentication sequence can observe use','Resource-side Kerberos authentication - strong','4769 and service access correlation','public_stronger','Public compensation can confirm security effect after submission.') ); missO='Submission success/result, target LUID sensitivity, subsequent use, caller trust and cross-user mutation.'; missP='Direct mutation and purge.'; missB='Mutation when EDR lacks API telemetry and the ticket is never used during retention.'; edge='Approved SSO and IR tools submit/purge tickets. API telemetry may expose caller LUID but not target LUID consistently. A purge may be routine troubleshooting rather than concealment.'; signals=@(@('KerbSubmitTicketMessage','strong','ours','Direct ticket mutation operation.'),@('KerbPurgeTicketCacheMessage','moderate','ours','Direct but commonly administrative.'),@('Subsequent Kerberos service use','strong','public','Confirms effect but is not uniquely malicious.')); pubWeak='Post-use behavior cannot establish how the ticket entered the cache and misses unused mutations.'; ourWeak='Combines submit and purge despite different risk and does not require success or follow-on use.'; decision='Separate submit and purge branches, enrich with target LUID/caller trust, and add optional post-submission service-use confirmation.'},
@{n='rubeus_netonly_ticket_sequence'; p='PROC-007'; pub=@("$elastic/rules/windows/privilege_escalation_newcreds_logon_rare_process.toml"); branches=@(
@('Net-only session created','4624 Type 9 with host and LUID','Public detects first-seen NewCredentials process','Type 9 logon - weak','Rare process and actor baseline','public_stronger','Public covers unusual session creation even without API telemetry.'),
@('Ticket submitted into new session','Correlates submit API to same LUID','Not covered','Type 9 plus submit-to-same-LUID - strong','Subsequent Kerberos use by session','ours_stronger','The correlation is tightly aligned to the procedure.'),
@('Session used for remote access','Not required','Not required','Resource-side Kerberos use tied to LUID - strong','Network destination/service fan-out','different_scope','Both stop before confirming the session effect.') ); missO='Subsequent use, submit success, creator/child process, cross-host entity mapping and delayed submissions beyond five minutes.'; missP='Ticket submission; public rarity state may reset or be poisoned by common admin tools.'; missB='Net-only creation without 4624 collection or ticket submission without target-LUID API telemetry.'; edge='Runas /netonly and admin tooling are common. LUID formatting and reuse can break or misjoin the sequence. A five-minute window may be too short for staged workflows.'; signals=@(@('Type 9 plus same-LUID ticket submit','strong','ours','Ordered, entity-bound procedure signal.'),@('First-seen NewCredentials process','moderate','public','Covers precursor but rarity is mutable.'),@('Type 9 alone','weak','both','Common administrative behavior.')); pubWeak='Rarity and program-files exclusions can miss established or relocated tooling and do not show ticket injection.'; ourWeak='Depends on uncommon target-LUID API telemetry and does not confirm the submitted ticket was used.'; decision='Keep the same-LUID sequence as primary; add process rarity only as compensation and correlate subsequent Kerberos use where session identity is available.'},
@{n='rubeus_s4u_ticket_sequence'; p='PROC-005'; pub=@("$sentinel/Solutions/BloodHound Enterprise/Analytic Rules/KerberosDelegationOnTierZeroObjects.yaml"); branches=@(
@('Risky delegation relationship exists','Assumed external inventory but not tested','Public BloodHound rule covers delegation on Tier Zero objects','Delegation configuration edge - strong','Authoritative allowed-delegation inventory','public_stronger','Public covers the enabling condition.'),
@('S4U2Self/protocol transition','4769 description text plus two targets','Not covered','S4U-specific 4769 fields - strong if parsed','Service-account baseline','ours_stronger','Ours observes runtime impersonation activity.'),
@('S4U2Proxy reaches target services','Distinct target-service fan-out','Not covered','Unexpected delegation edge plus service target - strong','Resource-side impersonated access','ours_stronger','Public configuration rule cannot show use.') ); missO='Single-target abuse, authoritative allowed edges, impersonated user, forwardable flags, resource-side effect and parser-safe S4U fields.'; missP='Runtime S4U use.'; missB='Legitimate-looking use along an already authorized edge without identity-aware resource telemetry.'; edge='4769 descriptions rarely expose literal S4U labels consistently; TransitedServices semantics vary. Legitimate web front ends create frequent multi-target S4U activity.'; signals=@(@('Unexpected S4U edge','strong','ours plus inventory','Close to misuse and specific when the baseline is authoritative.'),@('Delegation on Tier Zero object','strong','public','High-risk precondition, not proof of use.'),@('Two target services','weak','ours','Fan-out alone is common in middleware.')); pubWeak='Configuration exposure does not detect exploitation and depends on BloodHound Enterprise data freshness.'; ourWeak='Claims an inventory comparison but implements only textual S4U matching and a two-target threshold; this is a major gap between description and logic.'; decision='Make the allowed-delegation-edge comparison explicit, add single-target Tier Zero/sensitive-user branches, and retain public configuration exposure as preventive context.'},
@{n='rubeus_service_ticket_or_renewal_anomaly'; p='PROC-002'; pub=@("$sentinel/Detections/SecurityEvent/PotentialKerberoast.yaml","$elastic/rules/windows/credential_access_kerberos_service_ticket_rc4.toml"); branches=@(
@('High-volume TGS acquisition','20 events or 10 services per source/user','Sentinel detects RC4/options service burst with historical comparison','RC4/options service-ticket burst - strong','Requester-to-service novelty','public_stronger','Public logic is more specific to roastable ticket acquisition.'),
@('New requester-to-service RC4 relationship','Only volume','Elastic new-terms rule covers first/infrequent RC4 relationship','New RC4 relationship - moderate','Service-account sensitivity','public_stronger','Public covers low-volume novelty.'),
@('Ticket renewal activity','4770 included in same volume','Not covered by compared public rules','Abnormal renewal rate/context - moderate','Ticket lifetime and source baseline','ours_stronger','Ours includes renewal, though with weak generic thresholds.') ); missO='Encryption/options, first-seen relationship, per-service sensitivity, distinct treatment of 4769 and 4770, low-and-slow acquisition.'; missP='Renewal anomalies and non-RC4 ticket fan-out.'; missB='Normal-volume requests for one high-value service and incomplete DC coverage.'; edge='Application servers and SSO create high cardinality. RC4 may be legitimate for legacy services. A fixed ten-minute threshold does not transfer across environments.'; signals=@(@('RC4/options burst','strong','public','More closely matches roastable ticket collection.'),@('First-seen RC4 relationship','moderate','public','Useful low-volume context but depends on history.'),@('Generic 4769/4770 volume','weak','ours','Broad and noisy without ticket properties.')); pubWeak='RC4 focus misses AES and legitimate legacy environments need tuning; historical novelty depends on stable retention.'; ourWeak='Combines acquisition and renewal and uses fixed generic volume without ticket result, encryption or options.'; decision='Split 4769 acquisition from 4770 renewal; add encryption/options, rarity and sensitive-service branches; retain generic fan-out only as a lower-confidence signal.'},
@{n='rubeus_ticket_artifact_access_or_creation'; p='PROC-008,PROC-009,PROC-010,PROC-013'; pub=@("$elastic/rules/windows/credential_access_posh_kerb_ticket_dump.toml"); branches=@(
@('Ticket extracted in memory','Not covered unless written','Public PowerShell rule detects retrieval API strings','Retrieve API/script content - strong','EDR authentication-package telemetry','public_stronger','Public covers an in-memory extraction branch.'),
@('Ticket artifact written or read','Extension/name regex','Not required by public rule','File create/read of ticket artifact - moderate','File content/type and process trust','ours_stronger','Ours covers cross-tool disk artifacts.'),
@('Ticket parsed/converted without expected extension','Only name-based match','Not covered','File content signature or process-context cluster - moderate','Subsequent ticket submission/use','insufficient_evidence','Both can miss renamed or memory-only conversion.') ); missO='In-memory handling, content-aware artifact identification, archive/output directory context, signer/process trust, write-read-submit sequence.'; missP='Non-PowerShell artifacts and disk conversion paths.'; missB='Memory-only parsing or artifacts stored in telemetry-blind locations.'; edge='Extensions are mutable and .ccache is legitimate on Unix-like systems. File-read telemetry is uncommon and high volume. “asrep” or “kerberoast” substrings can occur in benign research files.'; signals=@(@('Authentication-package retrieval API','strong','public','Direct extraction operation within PowerShell coverage.'),@('Known ticket extension create/read','moderate','ours','Effect artifact, but mutable and legitimate in labs/admin.'),@('Filename substring only','weak','ours','Easy to collide with benign content and not causally specific.')); pubWeak='PowerShell-specific and does not cover resulting artifact handling.'; ourWeak='Relies on mutable names/extensions, groups four procedures, and misses memory-only behavior.'; decision='Keep artifact detection as compensation, lower substring-only confidence, add file-content/type and process-context branches, and link extraction-to-artifact-to-submit when telemetry permits.'},
@{n='rubeus_ticket_use_without_credible_kdc_issue'; p='PROC-008,PROC-009'; pub=@("$sentinel/Solutions/Alsid For AD/Analytic Rules/GoldenTicket.yaml","$elastic/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml"); branches=@(
@('Forged or mutated ticket used at service','Kerberos service use with PAC anomaly','Alsid emits vendor Golden Ticket alert; Elastic observes Kerberos network/auth sequence','Resource-side PAC/identity anomaly - strong','Vendor identity analytic','complementary','Ours states the raw effect; public supplies alternate analytic/process context.'),
@('No credible KDC issuance exists','Requires zero matching 4769 for 12 hours','Public rules do not require issuance absence','Complete multi-DC issuance absence - moderate','Cross-DC replication and referral-aware correlation','ours_stronger','Unique branch, but only trustworthy with complete telemetry.'),
@('Ticket use resembles normal activity','PAC anomaly required','Vendor analytic may use proprietary context; Elastic process sequence can add endpoint evidence','Multiple independent anomalies - strong','Rare process/source/service baseline','complementary','Layering can raise confidence without treating absence alone as proof.') ); missO='Cross-realm referrals, cached ticket lifetime, DC completeness proof, clock skew, identity aliases, silver-ticket cases with no DC contact, and resource-specific PAC fields.'; missP='Transparent raw-event explanation for proprietary Golden Ticket alert; issuance-absence branch.'; missB='Forged tickets whose PAC and use look valid and where resource telemetry lacks anomaly fields.'; edge='Missing one DC invalidates absence. Cached tickets legitimately outlive the search window. Source NAT and service aliases break joins. Vendor alert semantics are opaque.'; signals=@(@('Resource-side PAC/identity anomaly','strong','ours','Close to validation failure or identity inconsistency.'),@('No matching 4769','moderate','ours','Useful only with provably complete DC logs.'),@('Vendor Golden Ticket alert','moderate','public','Potentially strong but opaque and product-dependent.')); pubWeak='Alsid rule merely forwards a vendor codename; Elastic sequence is broad and neither exposes complete forgery reasoning.'; ourWeak='Depends on a nonstandard identity_or_pac_anomaly field and a fragile 12-hour absence join; cannot safely operate with incomplete DC telemetry.'; decision='Gate the rule on DC coverage health, separate PAC-anomaly and issuance-absence branches, and ingest vendor alerts as independent corroboration rather than ground truth.'},
@{n='rubeus_unusual_kerberos_password_change'; p='PROC-012'; pub=@("$sentinel/Detections/MultipleDataSources/MultiplePasswordresetsbyUser.yaml","$elastic/rules/windows/persistence_remote_password_reset.toml"); branches=@(
@('Password change/reset occurs','4723 or 4724 for two targets','Sentinel detects multiple resets; Elastic covers remote reset context','Account-change event - moderate','Kerberos password-service network attribution','equivalent','All cover the generic account-management effect.'),
@('Kerberos password-change protocol/process used','Advertised prerequisite but not present in condition','Public rules do not identify Kerberos password service','Process-attributed kpasswd traffic - strong','Caller process and destination port/service','insufficient_evidence','No implemented rule covers the Rubeus-specific transport branch.'),
@('Single sensitive account changed','Below two-target threshold','Remote-reset/public context may cover one account','Sensitive-account change - strong','Privileged actor/source baseline','public_stronger','Public context can detect targeted single-account changes.') ); missO='Single target, process/network attribution, change versus reset distinction, privileged target sensitivity and success/result.'; missP='Kerberos password-change protocol attribution.'; missB='Attribution to Rubeus when only ordinary account-change events exist.'; edge='Helpdesk and identity systems legitimately change many accounts. 4723/4724 may be emitted on different systems and actor normalization varies. Machine password rotation can dominate volume.'; signals=@(@('Sensitive account password changed by unusual actor/source','strong','public compensation','Security effect plus context.'),@('Two target changes','moderate','ours/public','Behavioral burst but common in administration.'),@('Ordinary 4723/4724','weak','both','Cannot attribute implementation.')); pubWeak='Generic reset logic does not identify Kerberos password-change transport and can be noisy for helpdesk operations.'; ourWeak='The rule claims process-attributed Kerberos password-service coverage but implements only two-target 4723/4724 cardinality.'; decision='Correct the description/implementation mismatch; add a distinct process-attributed kpasswd branch if telemetry exists and a sensitive-single-account branch. Keep generic multi-target logic compensating only.'}
)

$proposals = @{
'rubeus_as_request_anomaly' = @{type='compensating_rule'; branches='Failed or atypical-preauthentication AS probing that does not reach the existing generic fan-out threshold.'; telemetry='DC Security 4768; source IP, target account, result/action and normalized PreAuthType.'; code=@'
rule rubeus_as_request_failed_preauth_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-001"
  events:
    $e.metadata.product_event_type = "4768"
    $e.security_result.action != "ALLOW"
    $e.principal.ip = $source
    $e.target.user.userid = $account
  match:
    $source over 10m
  outcome:
    $accounts = count_distinct($account)
  condition:
    $e and $accounts >= 3
}
'@; why='Separates failed AS probing from successful TGT acquisition, producing a clearer branch than the current all-4768 cardinality. It still depends on tenant-specific result normalization and can miss single-account probing.'}
'rubeus_asrep_roast_sequence' = @{type='compensating_rule'; branches='Targeted no-preauthentication request against one sensitive or unusually roastable account.'; telemetry='DC Security 4768 with normalized PreAuthType plus an independently maintained account-risk enrichment.'; code=@'
rule rubeus_asrep_roast_sensitive_account {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-003"
  events:
    $e.metadata.product_event_type = "4768"
    $e.additional.fields["PreAuthType"].value.string_value = "0"
    $e.additional.fields["account_risk_tier"].value.string_value = "high"
    $e.principal.ip = $source
    $e.target.user.userid = $account
  condition:
    $e
}
'@; why='Closes the single-account gap without weakening the existing multi-account rule. The risk tier must come from authoritative identity enrichment; a hard-coded account list would be too fragile.'}
'rubeus_kerberoast_sequence' = @{type='compensating_rule'; branches='Kerberoasting without visible LDAP reconnaissance, including low-volume RC4 service-ticket acquisition.'; telemetry='DC Security 4769 with encryption type, ticket options, requester, service/SPN, source and an approved legacy-service enrichment.'; code=@'
rule rubeus_kerberoast_rc4_service_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-004"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["TicketEncryptionType"].value.string_value = "0x17"
    $e.additional.fields["approved_legacy_rc4_service"].value.bool_value = false
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 15m
  outcome:
    $services = count_distinct($service)
  condition:
    $e and $services >= 3
}
'@; why='Adds ticket-property specificity and works when LDAP telemetry is missing. The threshold and legacy-service enrichment require local testing; AES and single-SPN branches remain separate gaps.'}
'rubeus_kerberos_over_http_proxy' = @{type='rewrite'; branches='Kerberos-over-HTTP attributed to an unapproved process and destination, rather than alerting on every legitimate KDC-proxy request.'; telemetry='Process-attributed HTTP telemetry with Content-Type, destination, signer/process identity, and approved KDC-proxy enrichment.'; code=@'
rule rubeus_kerberos_over_http_unapproved_process {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-013"
  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.additional.fields["http_request_content_type"].value.string_value = "application/kerberos" nocase
    $e.additional.fields["approved_kdc_proxy_client"].value.bool_value = false
    $e.additional.fields["approved_kdc_proxy_destination"].value.bool_value = false
    $e.principal.process.file.full_path != ""
  condition:
    $e
}
'@; why='Makes the rule match its description and turns a protocol-only signal into an attributed, policy-aware branch. It still misses encrypted traffic where Content-Type is unavailable, so process/destination compensation remains necessary.'}
'rubeus_lsa_ticket_cache_operations' = @{type='split'; branches='High-risk ticket retrieval separated from lower-confidence cache enumeration.'; telemetry='EDR authentication-package API telemetry with caller process, Kerberos message type, target LUID, result and ticket count when available.'; code=@'
rule rubeus_lsa_encoded_ticket_retrieval {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-006"
  events:
    $e.metadata.product_event_type = "EDR_API_CALL"
    $e.additional.fields["api_name"].value.string_value = "LsaCallAuthenticationPackage"
    re.regex($e.additional.fields["kerberos_message_type"].value.string_value,
      `Kerb(RetrieveEncodedTicket|RetrieveTicket)`) nocase
    $e.security_result.action = "ALLOW"
  condition:
    $e
}
'@; why='A separate retrieval rule preserves a strong causal signal without assigning the same severity to ordinary cache queries. A second lower-severity query/triage rule should add cross-LUID breadth and caller-trust context.'}
'rubeus_lsa_ticket_mutation' = @{type='split'; branches='Successful ticket submission separated from cache purge.'; telemetry='EDR LsaCallAuthenticationPackage telemetry with Kerberos message type, result, caller and target LUID.'; code=@'
rule rubeus_lsa_ticket_submission {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-007"
  events:
    $e.metadata.product_event_type = "EDR_API_CALL"
    $e.additional.fields["api_name"].value.string_value = "LsaCallAuthenticationPackage"
    $e.additional.fields["kerberos_message_type"].value.string_value = "KerbSubmitTicketMessage"
    $e.security_result.action = "ALLOW"
    $e.additional.fields["target_luid"].value.string_value = $luid
  condition:
    $e
}
'@; why='Prevents purge activity from diluting the stronger ticket-submission branch and requires a successful operation. Purge should remain a separate moderate-severity rule with repetition or suspicious caller context.'}
'rubeus_netonly_ticket_sequence' = @{type='rewrite'; branches='Confirmation that the submitted ticket is used from the same net-only session.'; telemetry='4624 Type 9, EDR ticket-submit target LUID, and resource/endpoint Kerberos authentication tied to host and LUID.'; code=@'
rule rubeus_netonly_submit_and_use_sequence {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-007"
  events:
    $logon.metadata.product_event_type = "4624"
    $logon.additional.fields["LogonType"].value.string_value = "9"
    $logon.target.hostname = $host
    $logon.additional.fields["TargetLogonId"].value.string_value = $luid
    $submit.additional.fields["kerberos_message_type"].value.string_value = "KerbSubmitTicketMessage"
    $submit.principal.hostname = $host
    $submit.additional.fields["target_luid"].value.string_value = $luid
    $use.metadata.event_type = "USER_LOGIN"
    $use.security_result.auth_details = "KERBEROS"
    $use.principal.hostname = $host
    $use.additional.fields["subject_luid"].value.string_value = $luid
  match:
    $host, $luid over 30m
  condition:
    $logon and $submit and $use
}
'@; why='Adds the missing security-effect branch and extends the window for staged administration. It requires reliable LUID propagation; retain the existing two-event rule as a lower-confidence compensating alert where service-use LUID is unavailable.'}
'rubeus_s4u_ticket_sequence' = @{type='rewrite'; branches='Runtime S4U activity across an unauthorized delegation edge, including one sensitive target.'; telemetry='4769 with normalized S4U/delegation context plus authoritative allowed-edge and target-sensitivity enrichment.'; code=@'
rule rubeus_s4u_unauthorized_delegation_edge {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-005"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["delegation_flow"].value.string_value = /(S4U2Self|S4U2Proxy)/
    $e.additional.fields["delegation_edge_approved"].value.bool_value = false
    $e.target.user.userid = $service_account
    $e.target.resource.name = $target_service
  condition:
    $e
}
'@; why='Implements the delegation-edge comparison that the current rule only describes and catches a single unauthorized target. The enrichment must be authoritative and freshness-monitored; raw description-text matching should remain compensation only.'}
'rubeus_service_ticket_or_renewal_anomaly' = @{type='split'; branches='Service-ticket acquisition separated from ticket renewal, with RC4/legacy context.'; telemetry='DC Security 4769 with requester, service, encryption type and approved legacy-service enrichment; retain 4770 for a separate renewal baseline.'; code=@'
rule rubeus_unapproved_rc4_service_ticket_burst {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-002,PROC-004"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["TicketEncryptionType"].value.string_value = "0x17"
    $e.additional.fields["approved_legacy_rc4_service"].value.bool_value = false
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 10m
  outcome:
    $services = count_distinct($service)
  condition:
    $e and $services >= 3
}
'@; why='Replaces a weak combined 4769/4770 count with a more specific acquisition branch. Renewal needs its own account/source historical baseline; fixed public thresholds are not adopted without local distributions.'}
'rubeus_ticket_artifact_access_or_creation' = @{type='rewrite'; branches='Ticket artifact creation by an unapproved process, avoiding bare substring matches.'; telemetry='EDR file creation/read with extension, file type where available, caller signer/trust, and approved Kerberos-tool enrichment.'; code=@'
rule rubeus_ticket_artifact_from_unapproved_process {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-008,PROC-009,PROC-010,PROC-013"
  events:
    $e.metadata.event_type = "FILE_CREATION"
    re.regex($e.target.file.full_path, `\.(kirbi|ccache)$`) nocase
    $e.additional.fields["approved_kerberos_tool"].value.bool_value = false
    $e.principal.process.file.full_path != ""
  condition:
    $e
}
'@; why='Removes weak “asrep/kerberoast” substring matching and requires attributed creation by an unapproved process. It cannot cover memory-only handling; direct API and subsequent ticket-use rules remain required.'}
'rubeus_ticket_use_without_credible_kdc_issue' = @{type='rewrite'; branches='PAC/identity anomaly and KDC-issuance absence gated by explicit DC collection health.'; telemetry='Resource-side Kerberos use/PAC anomaly, complete 4769 from all authoritative DCs, and a collection-health event proving coverage for the window.'; code=@'
rule rubeus_ticket_use_without_issue_with_healthy_dc_coverage {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-008,PROC-009"
  events:
    $health.metadata.product_event_type = "COLLECTION_HEALTH"
    $health.additional.fields["all_domain_controllers_reporting"].value.bool_value = true
    $access.metadata.event_type = "USER_LOGIN"
    $access.security_result.auth_details = "KERBEROS"
    $access.additional.fields["identity_or_pac_anomaly"].value.bool_value = true
    $access.target.user.userid = $user
    $access.principal.ip = $source
    $access.target.resource.name = $service
    $tgs.metadata.product_event_type = "4769"
    $tgs.target.user.userid = $user
    $tgs.principal.ip = $source
    $tgs.target.resource.name = $service
  match:
    $user, $source, $service over 12h
  condition:
    $health and $access and #tgs = 0
}
'@; why='Prevents absence logic from firing when DC coverage is known to be incomplete. Production design must bind health to the same domain/window and account for referrals, cache lifetime and cross-realm issuance.'}
'rubeus_unusual_kerberos_password_change' = @{type='compensating_rule'; branches='Process-attributed Kerberos password-change traffic followed by the account-change effect, including one target.'; telemetry='Endpoint network telemetry for Kerberos password service (TCP/UDP 464) with process attribution plus 4723/4724 actor/target events.'; code=@'
rule rubeus_kpasswd_process_and_account_change {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-012"
  events:
    $net.metadata.event_type = "NETWORK_CONNECTION"
    $net.target.port = 464
    $net.principal.hostname = $host
    $net.principal.process.file.full_path = $process
    $change.metadata.product_event_type = /(4723|4724)/
    $change.principal.hostname = $host
    $change.principal.user.userid = $actor
    $change.target.user.userid = $target
  match:
    $host, $actor over 5m
  condition:
    $net and $change
}
'@; why='Adds the missing transport/process branch and can cover one account change. It still cannot attribute the change to Rubeus without caller trust/history, and port 464 is also used legitimately by native password workflows.'}
}

foreach ($s in $specs) {
  $internalPath = Join-Path $repoRoot "detections/rubeus/yaral/$($s.n).yaral"
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $internalPath).Hash.ToLowerInvariant()
  $publicLines = @(); foreach($p in $s.pub){$full=Join-Path $repoRoot $p;$ph=(Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash.ToLowerInvariant();$rel=$p.Substring('public-rules/'.Length).Replace('\','/');$publicLines += "- [``$p``](../../$rel) - SHA-256 ``$ph``"}
  $lines=@("# Public-rule comparison: $($s.n)",'','## Identity and independence gate','',"- Internal tool: ``rubeus``","- Internal canonical rule: ``detections/rubeus/yaral/$($s.n).yaral``","- Internal SHA-256: ``$hash``",'- Internal review completed before public comparison: `yes`',"- Procedure IDs: ``$($s.p)``",'- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.','', 'Public candidates:')+$publicLines+@('','## Procedure and detection-branch matrix','', '| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |','| --- | --- | --- | --- | --- | --- | --- |')
  foreach($b in $s.branches){$lines += '| '+(($b|ForEach-Object{$_.Replace('|','/')}) -join ' | ')+' |'}
  $lines += @('','## Missing detection branches','',"- Missing from ours: $($s.missO)","- Missing from public rule: $($s.missP)","- Missing from both: $($s.missB)",'','## Detection edge cases and blind spots','',$s.edge,'','## Signal-quality assessment','', '| Signal | Strength | Used by | Why | Benign prevalence / fragility |','| --- | --- | --- | --- | --- |')
  foreach($sig in $s.signals){$lines += "| $($sig[0]) | $($sig[1]) | $($sig[2]) | $($sig[3]) | Requires tenant-specific validation and collection-health monitoring. |"}
  $proposal = $proposals[$s.n]
  $lines += @('','## Public-rule weaknesses','',$s.pubWeak,'','## Internal-rule weaknesses','',$s.ourWeak,'','## Decision trail','',"- Candidate improvement: $($s.decision)",'- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`','- Decision: `deferred_pending_rule_improvement_run`','- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`','- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`','','## Unmatched scope','',"Public candidates do not cover the full ``$($s.p)`` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.",'','## Proposed YARA-L improvement','',"- Change type: ``$($proposal.type)``","- Addresses branches: $($proposal.branches)","- Required telemetry: $($proposal.telemetry)",'- Validation status: `unvalidated_proposal`','','```yaral',$proposal.code.Trim(),'```','', $proposal.why,'','If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.')
  Set-Content -LiteralPath (Join-Path $outRoot "$($s.n).md") -Value $lines -Encoding utf8
}

$index=@('# Rubeus public-rule comparison index','','Pinned Rubeus revision: `74215f68ea70bd6a66c008da91bf5fe21d20b154`','','All 12 canonical Rubeus rules were compared from a threat-detection perspective. These comparisons identify improvements but deliberately do not alter canonical logic in the same pass; each accepted change must pass the normal adversarial review and regeneration gates.','','| Internal rule | Procedure | Headline conclusion |','| --- | --- | --- |')
foreach($s in $specs){$headline=($s.branches|ForEach-Object{$_[5]}|Sort-Object -Unique)-join ', ';$index += "| [$($s.n)](./$($s.n).md) | $($s.p) | $headline |"}
$index += @('','## Cross-rule findings','','- Strongest internal signals: direct LSA ticket submit/retrieve operations, same-LUID Type 9 plus ticket submission, no-preauthentication AS requests, and resource-side PAC/identity anomalies.','- Weakest internal signals: generic 4769/4770 volume, filename/extension matches, ordinary multi-target password changes, and S4U fan-out without an implemented delegation-edge baseline.','- Material missing branches: targeted single-account roasting, ticket encryption/options and requester-to-service novelty, process attribution for Kerberos-over-HTTP, caller trust and success for LSA operations, resource-side confirmation after ticket submission, and collection-health gating for KDC-issuance absence.','- Public rules are strongest where they add ticket-property specificity, first-seen relationships, PowerShell API-content coverage, rare NewCredentials process context, or risky delegation configuration. They are weaker where they are backend/product-specific, implementation-specific, RC4-only, or simply forward opaque vendor alerts.','','## Unmatched public scope','','No Chronicle community rule in the pinned public corpus materially matched these Rubeus procedure branches. Public rules for unrelated Kerberos attacks or configuration states were excluded unless they supplied a defensible compensating branch.','','## Review status','','Threat-detection comparison complete for 12/12 Rubeus rules. Canonical improvements are explicitly deferred to a separate rule-change run so external logic is not adopted blindly.')
Set-Content -LiteralPath (Join-Path $outRoot 'INDEX.md') -Value $index -Encoding utf8
Write-Host 'Wrote 12 Rubeus detection-engineering comparisons and one index.'
