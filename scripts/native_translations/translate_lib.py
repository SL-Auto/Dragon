"""Render native secondary translations from a per-rule correlation spec.

Spec kinds:
  single: one event leg, optional match keys, optional distinct-count/event-count thresholds.
  seq:    two ordered legs joined on keys within a window, optional distinct-count threshold.
Clauses: ('eq',col,val) ('num',col,n) ('in',col,[..]) ('re',col,pat) ('notre',col,pat)
         ('ne_true',col) ('false',col) ('or',[[clauses],[clauses],...])
Columns use one normalized vocabulary (declared in each file's field_mapping); EQL maps
columns to ECS through ECS_MAP; unmapped enrichment columns become labels.<col>.
"""
import pathlib, re

STATUS = "experimental_needs_backend_mapping_and_validation"
ECS_MAP = {
    "event_type": "event.action", "product_event_type": "event.code", "hostname": "host.name",
    "user_id": "user.id", "process_id": "process.entity_id", "process_path": "process.executable",
    "process_sha256": "process.hash.sha256", "process_signed": "process.code_signature.trusted",
    "process_prevalence": "labels.process_prevalence", "target_path": "file.path",
    "target_process_path": "labels.target_process_executable", "target_process_id": "labels.target_process_entity_id",
    "target_host": "destination.domain", "target_ip": "destination.ip", "target_port": "destination.port",
    "direction": "network.direction", "dns_query": "dns.question.name", "dns_type": "dns.question.type",
    "registry_key": "registry.key", "registry_value": "registry.value", "integrity_level": "process.Ext.token.integrity_level_name",
    "source_ip": "source.ip", "service_name": "service.name", "logon_type": "labels.logon_type",
    "command_line": "process.command_line", "parent_process_path": "process.parent.executable",
    "parent_process_id": "process.parent.entity_id", "user_agent": "user_agent.original",
    "original_file_name": "process.pe.original_file_name", "parent_command_line": "process.parent.command_line", "signer": "file.code_signature.subject_name",
}


def meta(text, name):
    m = re.search(r'(?m)^\s*' + re.escape(name) + r'\s*=\s*"([^"]*)"', text)
    return m.group(1) if m else ""


def q(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def sq(v):
    return "'" + str(v).replace("'", "''") + "'"


# ---------------------------------------------------------------- clause renderers
def spl(c):
    k = c[0]
    if k == "eq": return f'{c[1]}=={q(c[2])}'
    if k == "num": return f'{c[1]}=={c[2]}'
    if k == "in": return f'in({c[1]}, {", ".join(q(v) for v in c[2])})'
    if k == "re": return f'match({c[1]}, {q("(?i)" + c[2])})'
    if k == "notre": return f'NOT match(coalesce({c[1]},""), {q("(?i)" + c[2])})'
    if k == "ne_true": return f'(isnull({c[1]}) OR {c[1]}!="true")'
    if k == "false": return f'{c[1]}=="false"'
    if k == "or": return "(" + " OR ".join("(" + " AND ".join(spl(x) for x in g) + ")" for g in c[1]) + ")"
    raise ValueError(c)


def kql(c, p=""):
    k, col = c[0], (p + c[1] if len(c) > 1 and isinstance(c[1], str) else None)
    if k == "eq": return f'{col} == {q(c[2])}'
    if k == "num": return f'{col} == {c[2]}'
    if k == "in": return f'{col} in ({", ".join(q(v) for v in c[2])})'
    if k == "re": return f'{col} matches regex @"(?i){c[2].replace(chr(34), chr(34)*2)}"'
    if k == "notre": return f'not(coalesce({col}, "") matches regex @"(?i){c[2].replace(chr(34), chr(34)*2)}")'
    if k == "ne_true": return f'coalesce(tobool({col}), false) == false'
    if k == "false": return f'tobool({col}) == false'
    if k == "or": return "(" + " or ".join("(" + " and ".join(kql(x, p) for x in g) + ")" for g in c[1]) + ")"
    raise ValueError(c)


def sql(c, a=""):
    k = c[0]
    col = (a + "." if a else "") + c[1] if len(c) > 1 and isinstance(c[1], str) else None
    if k == "eq": return f'{col} = {sq(c[2])}'
    if k == "num": return f'{col} = {c[2]}'
    if k == "in": return f'{col} IN ({", ".join(sq(v) for v in c[2])})'
    if k == "re": return f"REGEXP_LIKE({col}, {sq(c[2])}, 'i')"
    if k == "notre": return f"NOT REGEXP_LIKE(COALESCE({col}, ''), {sq(c[2])}, 'i')"
    if k == "ne_true": return f'COALESCE({col}, FALSE) = FALSE'
    if k == "false": return f'{col} = FALSE'
    if k == "or": return "(" + " OR ".join("(" + " AND ".join(sql(x, a) for x in g) + ")" for g in c[1]) + ")"
    raise ValueError(c)


def ecs(col):
    return ECS_MAP.get(col, "labels." + col)


def eql(c):
    k = c[0]
    col = ecs(c[1]) if len(c) > 1 and isinstance(c[1], str) else None
    if k == "eq": return f'{col} == {q(c[2])}'
    if k == "num": return f'{col} == {c[2]}'
    if k == "in": return f'{col} in ({", ".join(q(v) for v in c[2])})'
    if k == "re": return f'{col} regex~ {q(c[2])}'
    if k == "notre": return f'not {col} regex~ {q(c[2])}'
    if k == "ne_true": return f'({col} == null or {col} == false)'
    if k == "false": return f'{col} == false'
    if k == "or": return "(" + " or ".join("(" + " and ".join(eql(x) for x in g) + ")" for g in c[1]) + ")"
    raise ValueError(c)


def sigma_sel(clauses, prefix):
    """Return (selection dict lines by name, condition fragment)."""
    sels, cond = {}, []
    pos, neg, ors = [], [], []
    for c in clauses:
        if c[0] == "or": ors.append(c)
        elif c[0] in ("notre", "ne_true"): neg.append(c)
        else: pos.append(c)
    def lines(cs):
        out = []
        for c in cs:
            k = c[0]
            if k in ("eq", "num"): out.append(f"  {c[1]}: {q(c[2]) if k == 'eq' else c[2]}")
            elif k == "in": out += [f"  {c[1]}:"] + [f"    - {q(v)}" for v in c[2]]
            elif k == "re": out.append(f"  {c[1]}|re: {q('(?i)' + c[2])}")
            elif k == "notre": out.append(f"  {c[1]}|re: {q('(?i)' + c[2])}")
            elif k == "ne_true": out.append(f"  {c[1]}: true")
            elif k == "false": out.append(f"  {c[1]}: false")
        return out
    if pos:
        sels[f"{prefix}sel"] = lines(pos); cond.append(f"{prefix}sel")
    for i, o in enumerate(ors):
        names = []
        for j, g in enumerate(o[1]):
            n = f"{prefix}alt{i}_{j}"; sels[n] = lines(g); names.append(n)
        cond.append(f"1 of {prefix}alt{i}_*")
    for i, c in enumerate(neg):
        n = f"{prefix}filter{i}"; sels[n] = lines([c]); cond.append(f"not {n}")
    return sels, " and ".join(cond)


# ---------------------------------------------------------------- file writers
def header(text, src, prefix, fidelity, schema, fmap, gaps, rule):
    rows = [f"source_yaral: {src}", f"translation_status: {STATUS}", f"fidelity: {fidelity}", f"rule_name: {rule}",
            f"severity: {meta(text, 'severity').lower()}", f"procedure_ids: {meta(text, 'procedure_ids')}",
            f"description: {meta(text, 'description')}", f"log_source_prerequisites: {meta(text, 'log_source_prerequisites')}",
            f"false_positives: {meta(text, 'false_positives')}", f"references: {meta(text, 'references')}",
            f"schema_profile: {schema}", f"field_mapping: {fmap}", f"assumptions_and_gaps: {gaps}"]
    return "\n".join(prefix + r for r in rows) + "\n"


def render(tool_dir, spec):
    rule = spec["name"]
    ypath = tool_dir / "yaral" / f"{rule}.yaral"
    text = ypath.read_text(encoding="utf-8")
    src = f"detections/{tool_dir.name}/yaral/{rule}.yaral"
    w = spec["window"]  # minutes
    keys = spec.get("keys", [])
    fmap = "normalized columns (" + ", ".join(spec["columns"]) + "); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name"
    base_gap = spec.get("note", "")
    out = {}
    if spec["kind"] == "single":
        leg = spec["legs"][0]
        cnt = spec.get("count")  # (col, n) distinct, or ("#", n) events
        agg_spl = agg_kql = agg_sql = None
        sched = f" Hop window approximated by scheduling every {max(5, w // 3)} minutes over the trailing {w} minutes." if keys else ""
        g = (f"Native filter{', grouping by ' + ', '.join(keys) if keys else ''}{' and threshold' if cnt else ''}.{sched} {base_gap}").strip()
        where_spl = " AND ".join(spl(c) for c in leg["where"])
        where_kql = "\n    and ".join(kql(c) for c in leg["where"])
        where_sql = "\n  AND ".join(sql(c) for c in leg["where"])
        lines_spl = [f"| search index=<configured_index> earliest=-{w}m@m latest=now", f"| where {where_spl}"]
        lines_kql = ["NormalizedEvents", f"| where TimeGenerated > ago({w}m)", f"| where {where_kql}"]
        sql_sel, sql_group, sql_having = ["hostname"], "", ""
        vals = spec.get("values", [])
        if keys:
            if cnt and cnt[0] != "#":
                lines_spl.append(f"| stats dc({cnt[0]}) as matched_count " + " ".join(f"values({v}) as {v}_values" for v in vals) + f" by {' '.join(keys)}")
                lines_spl.append(f"| where matched_count >= {cnt[1]}")
                lines_kql.append(f"| summarize MatchedCount = count_distinct({cnt[0]})" + "".join(f", {v}_values = make_set({v}, 20)" for v in vals) + f" by {', '.join(keys)}")
                lines_kql.append(f"| where MatchedCount >= {cnt[1]}")
                sql_sel = keys + [f"COUNT(DISTINCT {cnt[0]}) AS matched_count"]; sql_group = "GROUP BY " + ", ".join(keys); sql_having = f"HAVING COUNT(DISTINCT {cnt[0]}) >= {cnt[1]}"
            else:
                n = cnt[1] if cnt else 1
                lines_spl.append(f"| stats count as matched_count " + " ".join(f"values({v}) as {v}_values" for v in vals) + f" by {' '.join(keys)}")
                lines_spl.append(f"| where matched_count >= {n}")
                lines_kql.append(f"| summarize MatchedCount = count()" + "".join(f", {v}_values = make_set({v}, 20)" for v in vals) + f" by {', '.join(keys)}")
                lines_kql.append(f"| where MatchedCount >= {n}")
                sql_sel = keys + ["COUNT(*) AS matched_count"]; sql_group = "GROUP BY " + ", ".join(keys); sql_having = f"HAVING COUNT(*) >= {n}"
        else:
            sql_sel = ["*"]
        lines_spl.append(f'| eval canonical_rule="{rule}"')
        lines_kql.append(f'| extend CanonicalRule = "{rule}"')
        sqltxt = [f"-- Schema assumption: normalized_events with columns {', '.join(['event_time'] + spec['columns'])}.",
                  f"SELECT {', '.join(sql_sel)}, {sq(rule)} AS canonical_rule", "FROM normalized_events",
                  f"WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '{w}' MINUTE", f"  AND {where_sql}"] + ([sql_group] if sql_group else []) + ([sql_having + ";"] if sql_having else [])
        if not sql_having: sqltxt[-1] += ";"
        fid = "high"
        out["spl"] = header(text, src, "# ", fid, "schemas/splunk-cim.yml", fmap, g, rule) + "\n".join(lines_spl) + "\n"
        out["kql"] = header(text, src, "// ", fid, "schemas/sentinel-asim.yml", fmap, g + " NormalizedEvents is a placeholder for the tenant table or ASIM parser.", rule) + "\n".join(lines_kql) + "\n"
        out["sql"] = header(text, src, "-- ", fid, "schemas/normalized-sql.yml", fmap, g + " Regex and interval syntax are dialect-specific.", rule) + "\n".join(sqltxt) + "\n"
        eql_fid = "partial" if cnt else "high"
        eg = ("EQL selects matching events but cannot aggregate; implement the grouping threshold in ES|QL or a threshold rule. " if cnt else "Native single-event filter. ") + base_gap
        out["eql"] = header(text, src, "// ", eql_fid, "schemas/elastic-ecs.yml", fmap, eg.strip(), rule) + "any where " + "\n  and ".join(eql(c) for c in leg["where"]) + "\n"
        sels, cond = sigma_sel(leg["where"], "")
        corr = None
        if cnt and keys:
            corr = ["type: " + ("event_count" if cnt[0] == "#" else "value_count"), "rules:", f"  - {rule}_base", "group-by:"] + [f"  - {k}" for k in keys] + [f"timespan: {w}m", "condition:"] + ([f"  gte: {cnt[1]}"] if cnt[0] == "#" else [f"  field: {cnt[0]}", f"  gte: {cnt[1]}"])
        out["sigma"] = sigma_file(text, src, rule, "high", fmap, ("Base rule plus Sigma correlation for the threshold. " if corr else "Single-event Sigma rule. ") + base_gap, spec["sigma"], [(f"{rule}_base" if corr else rule, sels, cond)], corr)
    else:
        a, b = spec["legs"]
        jk = keys
        cnt = spec.get("count")  # (leg, col, n)
        sched = f"Scheduled every {max(5, w // 3)} minutes over the trailing {2 * w} minutes."
        g = f"Native ordered two-event correlation on {', '.join(jk)} within {w} minutes (first event before second). {base_gap}".strip()
        def derive_spl(leg):
            return [f'| rex field={src_col} "{pat_named(pat, col)}"' for col, (src_col, pat) in leg.get("derive", {}).items()]
        def derive_kql(leg):
            return [f'| extend {col} = extract(@"(?i){pat.replace(chr(34), chr(34) * 2)}", 1, {src_col})' for col, (src_col, pat) in leg.get("derive", {}).items()]
        # SPL: tag legs, aggregate per key, compare first-a and last-b times
        wa = " AND ".join(spl(c) for c in a["where"]); wb = " AND ".join(spl(c) for c in b["where"])
        s = [f"| search index=<configured_index> earliest=-{2 * w}m@m latest=now",
             f'| eval leg=case({wa}, "a", {wb}, "b")', "| where isnotnull(leg)"]
        for kk in jk:
            if src_of(a, kk) != kk or src_of(b, kk) != kk:
                s.append(f'| eval {kk}=case(leg="a", {src_of(a, kk)}, leg="b", {src_of(b, kk)})')
        for leg, tag in ((a, "a"), (b, "b")):
            for col, (src_col, pat) in leg.get("derive", {}).items():
                s.append(f'| rex field={src_col} "{pat_named(pat, col)}"')
        cnt_spl = f" dc(eval(if(leg=\"{cnt[0]}\", {cnt[1]}, null()))) as matched_count" if cnt else ""
        s += [f'| stats min(eval(if(leg="a", _time, null()))) as first_a max(eval(if(leg="b", _time, null()))) as last_b{cnt_spl} by {" ".join(jk)}',
              f"| where isnotnull(first_a) AND isnotnull(last_b) AND first_a <= last_b AND last_b - first_a <= {w * 60}"]
        if cnt: s.append(f"| where matched_count >= {cnt[2]}")
        s.append(f'| eval canonical_rule="{rule}"')
        spl_gap = g + " " + sched + " SPL compares the earliest first-leg and latest second-leg time per key, which is weaker than per-pair ordering."
        out["spl"] = header(text, src, "# ", "partial", "schemas/splunk-cim.yml", fmap, spl_gap, rule) + "\n".join(s) + "\n"
        # KQL: exact join
        ka = "\n    and ".join(kql(c) for c in a["where"]); kb = "\n    and ".join(kql(c) for c in b["where"])
        k = [f"let window = {w}m;", "let first_leg = NormalizedEvents", f"    | where TimeGenerated > ago({2 * w}m)", f"    | where {ka}"]
        k += ["    " + x for x in derive_kql(a)]
        k += [f"    | extend {kk} = {src_of(a, kk)}" for kk in jk if src_of(a, kk) != kk]
        k += ["    | project-rename FirstTime = TimeGenerated;", "let second_leg = NormalizedEvents", f"    | where TimeGenerated > ago({2 * w}m)", f"    | where {kb}"]
        k += ["    " + x for x in derive_kql(b)]
        k += [f"    | extend {kk} = {src_of(b, kk)}" for kk in jk if src_of(b, kk) != kk]
        k += ["    | project-rename SecondTime = TimeGenerated;", f"first_leg", f"| join kind=inner second_leg on {', '.join(jk)}", "| where SecondTime between (FirstTime .. FirstTime + window)"]
        if cnt:
            col = cnt[1] if cnt[0] == "a" else cnt[1] + "1" if cnt[1] in [c for c in spec["columns"]] else cnt[1]
            k += [f"| summarize MatchedCount = count_distinct({cnt[1] if cnt[0] == 'a' else cnt[1] + '1'}), FirstTime = min(FirstTime), LastTime = max(SecondTime) by {', '.join(jk)}", f"| where MatchedCount >= {cnt[2]}"]
        else:
            k += [f"| summarize FirstTime = min(FirstTime), LastTime = max(SecondTime), Pairs = count() by {', '.join(jk)}"]
        k.append(f'| extend CanonicalRule = "{rule}"')
        kgap = g + " Exact per-pair join; KQL suffixes duplicate right-side columns with 1."
        out["kql"] = header(text, src, "// ", "high", "schemas/sentinel-asim.yml", fmap, kgap + " NormalizedEvents is a placeholder for the tenant table or ASIM parser.", rule) + "\n".join(k) + "\n"
        # SQL: self join
        def sql_derive(leg, alias):
            return ", ".join(f"REGEXP_SUBSTR({src_col}, {sq(pat)}, 1, 1, 'i', 1) AS {col}" for col, (src_col, pat) in leg.get("derive", {}).items())
        da, db = sql_derive(a, "a"), sql_derive(b, "b")
        al = lambda leg: ", ".join(f"{src_of(leg, kk)} AS {kk}" for kk in jk if src_of(leg, kk) != kk)
        da = ", ".join(x for x in (da, al(a)) if x); db = ", ".join(x for x in (db, al(b)) if x)
        sa = "\n    AND ".join(sql(c) for c in a["where"]); sb = "\n    AND ".join(sql(c) for c in b["where"])
        cols = ", ".join(spec["columns"])
        sqltxt = [f"-- Schema assumption: normalized_events with columns event_time, {cols}.",
                  "WITH first_leg AS (", f"  SELECT *{', ' + da if da else ''} FROM normalized_events",
                  f"  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '{2 * w}' MINUTE", f"    AND {sa}"," ),",
                  "second_leg AS (", f"  SELECT *{', ' + db if db else ''} FROM normalized_events",
                  f"  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '{2 * w}' MINUTE", f"    AND {sb}", ")",
                  f"SELECT {', '.join('a.' + x for x in jk)}, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time" + (f", COUNT(DISTINCT {cnt[0]}.{cnt[1]}) AS matched_count" if cnt else "") + f", {sq(rule)} AS canonical_rule",
                  "FROM first_leg a", "JOIN second_leg b", "  ON " + "\n AND ".join(f"a.{x} = b.{x}" for x in jk),
                  f" AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '{w}' MINUTE",
                  f"GROUP BY {', '.join('a.' + x for x in jk)}" + (f"\nHAVING COUNT(DISTINCT {cnt[0]}.{cnt[1]}) >= {cnt[2]};" if cnt else ";")]
        out["sql"] = header(text, src, "-- ", "high", "schemas/normalized-sql.yml", fmap, g + " Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.", rule) + "\n".join(sqltxt) + "\n"
        # EQL: native sequence
        derive = a.get("derive") or b.get("derive")
        eql_fid = "partial" if (cnt or derive) else "high"
        eg = f"Native EQL sequence with per-event join keys and maxspan={w}m. " + ("Distinct-count threshold must be applied in ES|QL over sequence results. " if cnt else "") + ("EQL cannot derive the join value from a regex capture; this sequence joins on host keys only and the file-name equality must be checked downstream. " if derive else "") + base_gap
        seq_keys = [x for x in jk if not (derive and x in derive)]
        e = [f"sequence with maxspan={w}m",
             "  [any where " + " and ".join(eql(c) for c in a["where"]) + "] by " + ", ".join(ecs(src_of(a, x)) for x in seq_keys),
             "  [any where " + " and ".join(eql(c) for c in b["where"]) + "] by " + ", ".join(ecs(src_of(b, x)) for x in seq_keys)]
        out["eql"] = header(text, src, "// ", eql_fid, "schemas/elastic-ecs.yml", fmap, eg.strip(), rule) + "\n".join(e) + "\n"
        sa_sel, sa_cond = sigma_sel(a["where"], "")
        sb_sel, sb_cond = sigma_sel(b["where"], "")
        sig_keys = [x for x in jk if not (derive and x in derive)]
        corr = ["type: temporal_ordered", "rules:", f"  - {rule}_first", f"  - {rule}_second", "group-by:"] + [f"  - {x}" for x in sig_keys] + [f"timespan: {w}m"]
        alias_keys = [x for x in sig_keys if src_of(a, x) != x or src_of(b, x) != x]
        if alias_keys:
            corr.append("aliases:")
            for x in alias_keys:
                corr += [f"  {x}:", f"    {rule}_first: {src_of(a, x)}", f"    {rule}_second: {src_of(b, x)}"]
        sig_fid = "partial" if (cnt or derive) else "high"
        sgap = "Two base rules plus a Sigma temporal_ordered correlation. " + ("The distinct-count threshold is not expressible in a temporal correlation and must be applied by the backend. " if cnt else "") + ("Regex-derived join values are not expressible in Sigma; the correlation groups on host keys only. " if derive else "") + base_gap
        out["sigma"] = sigma_file(text, src, rule, sig_fid, fmap, sgap.strip(), spec["sigma"], [(f"{rule}_first", sa_sel, sa_cond), (f"{rule}_second", sb_sel, sb_cond)], corr)
    ext = {"spl": ".spl", "kql": ".kql", "sql": ".sql", "eql": ".eql", "sigma": ".yml"}
    for fmt, body in out.items():
        p = tool_dir / fmt / f"{rule}{ext[fmt]}"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8", newline="\n")
    return {f: re.search(r"fidelity: (\w+)", b).group(1) for f, b in out.items()}


def src_of(leg, k):
    return leg.get("alias", {}).get(k, k)


def pat_named(pat, col):
    return "(?i)" + pat.replace("(", f"(?<{col}>", 1).replace("\\", "\\\\").replace('"', '\\"')


def sigma_file(text, src, rule, fidelity, fmap, gaps, logsource, docs, corr):
    level = meta(text, "severity").lower()
    out = []
    for i, (name, sels, cond) in enumerate(docs):
        if i: out.append("---")
        out += [f"title: {q(meta(text, 'description'))}", f"name: {name}", "status: experimental",
                f"description: {q(meta(text, 'description'))}"]
        if i == 0:
            out += [f"source_yaral: {q(src)}", f"translation_status: {STATUS}", f"fidelity: {fidelity}",
                    "schema_profile: schemas/sigma.yml", f"field_mapping: {q(fmap)}", f"assumptions_and_gaps: {q(gaps)}",
                    "references:", f"  - {q(meta(text, 'references'))}", f"procedure_ids: {q(meta(text, 'procedure_ids'))}",
                    f"log_source_prerequisites: {q(meta(text, 'log_source_prerequisites'))}"]
        out += ["logsource:"] + [f"  {k}: {v}" for k, v in logsource.items()] + ["detection:"]
        for sname, lines in sels.items():
            out.append(f"  {sname}:"); out += ["  " + l for l in lines]
        out += [f"  condition: {cond}", "falsepositives:", f"  - {q(meta(text, 'false_positives'))}", f"level: {level}"]
    if corr:
        out += ["---", f"title: {q(meta(text, 'description'))}", f"name: {rule}", "status: experimental", "correlation:"] + ["  " + l for l in corr] + [f"level: {level}"]
    return "\n".join(out) + "\n"
