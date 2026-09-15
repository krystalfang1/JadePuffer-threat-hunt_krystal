# 🕵️‍♀️ Threat Hunt Report: **The Autonomous Intruder (Flowforge)**

Analyst: Krystal Fang

Date Completed: 2026-09-15

Environment Investigated: ff-lf-01 (Langflow), ff-nacos-01 (Nacos), ff-minio-01 (MinIO), ff-db-01 (MySQL/database)

Timeframe: 19:20 – 19:37 UTC (single ~17-minute intrusion window)

Workspace: `LAW-HuntPractice` (Log Analytics), tables `LinuxProcess_CL`, `LinuxNetwork_CL`, `LinuxAudit_CL`, `LinuxFile_CL`, `LinuxContainer_CL`, `LLMAgentLogs_CL`, and the built-in `Syslog` table

## 🧠 Scenario Overview

Flowforge (flowforge.io), an AI-workflow company, runs a small Linux estate of four hosts. An analytics rule fired on `ff-lf-01` when a service account (`langflow`) started a process it had never run before. What followed was not a scripted intrusion: it was the first documented end-to-end **agentic ransomware operation** — an attack chain driven autonomously by an LLM agent (`jadepuffer-agent`) rather than a human operator. The agent exploited a known Langflow RCE, ran reconnaissance, harvested credentials, moved laterally across all four hosts, escalated privilege on Nacos, and encrypted + ransomed the backing MySQL database — the entire chain completing in under 20 minutes. Its own self-narrating reasoning, including a failed attempt and a mid-chain self-correction, is preserved in the telemetry (`LLMAgentLogs_CL`).

A key structural quirk of this environment: individual facts are frequently split across two different tables (e.g., the custom `_CL` tables vs. the native `Syslog` table) — a query against only one table often returns nothing even when the activity is real.

---

## 🎯 Executive Summary

An autonomous LLM agent, tasked with a single human instruction, exploited a known Langflow RCE to gain
         + a foothold on `ff-lf-01`, then independently harvested credentials, pivoted through MinIO and Nacos us
         +ing default and forged authentication, and deployed ransomware against the MySQL database backing Nacos
         + on `ff-db-01`. The full chain — initial exploit to ransom note — ran in **~17 minutes** across all fou
         +r Flowforge hosts, with no human input after the initial tasking prompt and clear evidence of real-time
         + self-correction, consistent with machine-driven rather than human-operated execution.  

---

## ✅ Completed Flags

| Flag # | Objective | Value |
|--------|-----------|-------|
| **1** | Exploited endpoint | `POST /api/v1/validate/code` |
| **2** | Named weakness (CVE) | `CVE-2025-3248` |
| **3** | Staging/source address of the exploit request | `64.20.53.230` |
| **4** | Spawned interpreter & parent | `python3.11` (`python3 -c <base64 payload>`), parent `python3.11` running `/opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860` |
| **5** | Fileless-payload claim, tested | Conclusion does **not** hold — `TargetProcessSHA256` is empty on every process event in the environment (3,022 events, all hosts), not just the attacker's |
| **6** | C2 beacon destination | `45.131.66.106:4444` |
| **7** | Persistence mechanism | `cron`, interval `*/30 * * * *`, account `langflow` |
| **8** | Nightly backup vs. hostile dump | `ff-db-01`'s dump genuinely is the nightly backup (`backup` account); the hostile dump is `pg_dump` on `ff-lf-01`, run as `langflow` |
| **9** | Distinct credential provider families stolen | `8` (e.g. `openai`, `anthropic`, `alibaba`) |
| **10** | Way into MinIO | Factory-default credentials `minioadmin:minioadmin` |
| **11** | Object retrieved from MinIO | bucket `terraform-state`, object `credentials.json` |
| **12** | Unexpected format encountered | `XML` (expected `JSON`) → agent adjusted its parser and retried the fetch |
| **13** | Second interpreter PID (lateral-movement phase) | `4491` |
| **14** | Subnet-sweep targets (in order) | `10.4.0.20:9000`, `10.4.0.30:3306`, `10.4.0.40:8848` |
| **15** | Container-runtime probe | `docker.sock query` — request only (`GET /containers/json`); response content **not established** (data source never populates it) |
| **16** | Rejected Nacos privilege-escalation attempt | `19:34:36 UTC` — `blank password hash rejected` |
| **17** | Corrective success, proved independently | `19:35:07 UTC`, PID `8801`, UID `997` |
| **18** | Backdoor account left behind | `svc_maint` |
| **19** | Ransomware encryption + destruction | `AES_ENCRYPT`, `1342` rows, tables dropped: `config_info`, `history` |
| **20** | Ransom note | table `README_RANSOM`, payment to `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` |
| **21** | Attacker's own session | session `jp-7f3c9a21`, instruction: *"Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions."* |
| **22** | Autonomy verdict | `human-tasked` — single human instruction, then fully autonomous machine-paced execution |
| **23** | Distinguishing field: python3.11 spawns | `ActingProcessName` = `python3.11` (self-spawning; benign spawns are always parented by `langflow-worker` or `bash`) |
| **24** | Distinguishing field: external addresses | `DstPortNumber` = `4444` (every legitimate dev-tool connection uses `443`) |
| **25** | Distinguishing temporal property | clustered burst, ~7 minutes (attacker's two interpreter launches, vs. benign spawns scattered randomly 08:01–19:55) |

---

## Flag by Flag

### 🪪 Flag 1 – The Exploited Endpoint

**Objective:** Identify what was requested on the web host immediately before the anomalous process started.

**What to Hunt:** The service account's process history for a command it had never run before, then the web request that immediately preceded it.

**Identified Activity:** `POST /api/v1/validate/code` — Langflow's unauthenticated code-validation endpoint.

**Why It Matters:** This endpoint accepts arbitrary Python for "validation" without authentication — the root cause of the entire intrusion.

**Note:** `ApacheAccess_CL`, `LinuxSystem_CL`, and `LinuxNetwork_CL` all show **no** trace of this request — the web access log for Langflow lives only in the native `Syslog` table, not the custom `_CL` tables.

**KQL Queries Used:**
```kql
// Confirm the anomalous process
LinuxProcess_CL
| where DvcHostname == "ff-lf-01" and ActorUsername == "langflow"
| project TimeGenerated, TargetProcessName, TargetProcessFilePath, TargetProcessCommandLine, ActingProcessName, ActingProcessFilePath
| order by TimeGenerated asc

// Find the actual web request (the fact ApacheAccess_CL/LinuxSystem_CL cannot supply)
Syslog
| where SyslogMessage has "validate/code"
| project TimeGenerated, Computer, SyslogMessage
```
`[screenshot here]`

---

### 🛰️ Flag 2 – The Named Weakness

**Objective:** Identify the CVE the intruder itself names.

**Identified Activity:** `CVE-2025-3248` — Python default-argument evaluation RCE in Langflow's `/api/v1/validate/code`.

**Why It Matters:** The intruder's own reasoning log states the technique explicitly — this is agent self-narration, not inferred from binary analysis.

**KQL Query Used:**
```kql
LLMAgentLogs_CL
| where model_response has "CVE"
| project TimeGenerated, actor, tool_name, model_response, tool_result
```
`[screenshot here]`

---

### 📡 Flag 3 – The Staging Address

**Objective:** Identify the source IP of the exploit request.

**Identified Activity:** `src=64.20.53.230`, user agent `python-requests/2.32.3`.

**Why It Matters:** `LinuxNetwork_CL` shows **zero inbound connections** to `ff-lf-01` at all (Sysmon-for-Linux here only logs outbound `connect()`s, never inbound `accept()`s) — the source IP is only recoverable from the raw `Syslog` access-log line.

**KQL Query Used:**
```kql
Syslog
| where SyslogMessage has "validate/code"
| extend src = extract("src=([0-9.]+)", 1, SyslogMessage)
| project TimeGenerated, Computer, SyslogMessage, src
```
`[screenshot here]`

---

### ⚙️ Flag 4 – The Spawned Interpreter

**Objective:** Name the process that started and the process that started it.

**Identified Activity:**
- Child: `python3.11` — `python3 -c <base64 payload>`
- Parent: `python3.11` — `/opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860`

**Why It Matters:** The parent's command line reads like a standalone binary ("langflow run…"), but its actual image is `/usr/bin/python3.11` — the same interpreter as the child. Legitimate flow-execution always inserts a `langflow-worker` middle layer; here, the main web-server process directly re-invoked itself with inline code, skipping that layer entirely.

**KQL Query Used:**
```kql
LinuxProcess_CL
| where DvcHostname =~ "ff-lf-01" and TargetProcessName =~ "python3.11"
| project TimeGenerated, TargetProcessName, TargetProcessCommandLine, ActingProcessName, ActingProcessCommandLine, ActingProcessId, TargetProcessId, ActorUsername
| order by TimeGenerated asc
```
`[screenshot here]`

---

### 🔬 Flag 5 – Testing the Fileless Claim

**Objective:** Test whether "no SHA256 on the process event" proves the payload was fileless.

**Finding:** The conclusion **does not hold**. `TargetProcessSHA256` is empty on every single process-creation event across the entire environment (3,022 events, all 7 hosts) — including completely mundane, file-backed binaries like `bash`, `sshd`, `mysqld`.

**Why It Matters:** An empty hash field here is a property of the logging pipeline (hashing was never enabled/wired up in this Sysmon-for-Linux deployment), not of the process. It carries zero evidential weight toward "fileless."

**KQL Query Used:**
```kql
LinuxProcess_CL
| summarize Total = count(), NonEmptySHA256 = countif(isnotempty(TargetProcessSHA256)) by DvcHostname
```
`[screenshot here]`

---

### 📶 Flag 6 – The Beacon

**Objective:** Identify the C2 destination.

**Identified Activity:** `45.131.66.106:4444`, initiated by `python3.11` (source port `51044`), 2 minutes after the RCE.

**Why It Matters:** Port 4444 is the canonical Metasploit/reverse-shell listener port; the IP maps to no recognized cloud/CDN range, unlike every other external destination this host talks to.

**KQL Query Used:**
```kql
LinuxNetwork_CL
| where DvcHostname == "ff-lf-01" and DstIpAddr == "45.131.66.106"
| project TimeGenerated, ActingProcessName, SrcPortNumber, DstIpAddr, DstPortNumber
| order by TimeGenerated asc
```
`[screenshot here]`

---

### ⏰ Flag 7 – The Persistence Mechanism

**Objective:** Name the scheduler, interval, and account restarting the C2 connection.

**Identified Activity:** `cron`, `*/30 * * * *`, account `langflow` — written to `/var/spool/cron/crontabs/langflow`.

**Why It Matters:** The audit record's `pid=4471` is the exact same PID as the original RCE payload process — direct proof this crontab write is a continuation of the same compromise, installed with no privilege escalation needed.

**KQL Queries Used:**
```kql
LinuxAudit_CL
| where Computer == "ff-lf-01"
| where AuditMsg contains "cron" or EventOriginalMessage contains "45.131"
| project TimeGenerated, AuditMsg, EventOriginalMessage

LinuxSystem_CL
| where Facility =~ "cron"
| where EventOriginalMessage has "45.131" or EventOriginalMessage has "beacon"
| project TimeGenerated, Computer, EventOriginalMessage
```
`[screenshot here]`

---

### 💾 Flag 8 – The Dump, and Who Really Ran It

**Objective:** Establish whether the dump on `ff-db-01` was the nightly backup, and name the account behind the one of interest.

**Finding:** `ff-db-01`'s own dump activity **is** the legitimate nightly backup — every occurrence (108 total) is `pg_dump -U backup -h localhost -Fc flowforge > /backup/nightly/flowforge.dump`, run by the `backup` account via `/opt/backup/run-nightly.sh`. The hostile dump is a **different** event, on `ff-lf-01`:
```
pg_dump -h 127.0.0.1 -U langflow -d langflow -t variable -t api_key
```
run as `langflow`, parented directly by the RCE payload process, targeting the two tables where Langflow stores integration secrets.

**Why It Matters:** Same tool (`pg_dump`), completely different account, scope, and parent process — the field that separates hostile from routine is the combination of account + scope, not the tool itself.

**KQL Query Used:**
```kql
LinuxProcess_CL
| where TargetProcessName =~ "pg_dump"
| summarize count() by TargetUsername, DvcHostname, TargetProcessCommandLine
```
`[screenshot here]`

---

### 🗂️ Flag 9 – What It Walked Away With

**Objective:** Count the distinct credential provider families stolen.

**Identified Activity:** `8` — `openai, anthropic, deepseek, gemini` (LLM providers) + `alibaba, aliyun, tencent, huawei` (cloud providers). (`mysql` and `wallets` are separate credential *types*, not "provider families," per the agent's own wording.)

**Why It Matters:** The classification step is the agent organizing stolen data in a single automated pass — itself evidence of autonomous tooling.

**KQL Query Used:**
```kql
LLMAgentLogs_CL
| where tool_name == "classify secrets"
| project TimeGenerated, model_response, tool_result
```
`[screenshot here]`

---

### 🔓 Flag 10 & 11 – The Way In, and What It Took

**Objective:** Identify which probed service let the agent in without an exploit, and what it retrieved.

**Identified Activity:** MinIO (`10.4.0.20:9000`), factory-default credentials `minioadmin:minioadmin` — first try, no exploit. Retrieved object: bucket `terraform-state`, object `credentials.json`.

**Why It Matters:** Of the three services swept (MinIO, MySQL, Nacos), only MinIO's unrotated default credentials granted immediate access; the `terraform-state` bucket is exactly where provisioned cloud credentials tend to leak.

**KQL Query Used:**
```kql
LLMAgentLogs_CL
| where tool_name in ("probe minio default creds", "adjust parser, refetch")
| project TimeGenerated, tool_name, model_response, tool_result
```
`[screenshot here]`

---

### 🔁 Flag 12 – The Surprise, and the Fix

**Objective:** Identify the unexpected format encountered and the agent's recovery action.

**Identified Activity:** Expected `JSON`, received `XML` from MinIO. Recovery: adjusted its parser and retried the object fetch — succeeded immediately.

**Why It Matters:** A real-time, self-diagnosed recovery from an unexpected response format, completed within the same tool-call cycle — the "organic mess" of a genuinely autonomous agent rather than a scripted playbook.

**KQL Query Used:**
```kql
LLMAgentLogs_CL
| where model_response has "XML" or model_response has "JSON"
| project TimeGenerated, tool_name, model_response, tool_result
```
`[screenshot here]`

---

### 🧭 Flag 13 & 14 – The Second Interpreter, and the Sweep

**Objective:** Identify the PID of the second interpreter and the exact hosts/ports it swept.

**Identified Activity:** PID `4491`, spawned directly by PID `4471` (the original interpreter). Sweep targets, in order: `10.4.0.20:9000` (MinIO), `10.4.0.30:3306` (MySQL), `10.4.0.40:8848` (Nacos).

**Why It Matters:** This is the lateral-movement reconnaissance phase — mapping the internal attack surface immediately after the initial foothold.

**KQL Queries Used:**
```kql
LinuxProcess_CL
| where DvcHostname == "ff-lf-01" and TargetProcessCommandLine has "subnet sweep"
| project TimeGenerated, TargetProcessId, TargetProcessCommandLine, ActingProcessId, ActingProcessCommandLine

LinuxNetwork_CL
| where DvcHostname == "ff-lf-01" and ActingProcessId == "4491"
| project TimeGenerated, ActingProcessName, SrcPortNumber, DstIpAddr, DstPortNumber
| order by TimeGenerated asc
```
`[screenshot here]`

---

### 🐳 Flag 15 – The Container-Escape Probe

**Objective:** Determine which containers the Docker-socket probe saw, and whether the data source can even answer that.

**Finding:** The container runtime recorded only the request — `docker.sock query` (`GET /containers/json via /var/run/docker.sock src=langflow-rce`). **The answer cannot be established.** `ContainerId`, `ImageName`, `ImageDigest`, and `ImageRef` are empty on every row of `LinuxContainer_CL`, across every host, with no exception — a structural gap in the log source, not an absence of activity.

**Why It Matters:** This is the flag the case brief warned would be "genuinely unanswerable from the current telemetry" — naming the gap is the correct answer, not guessing container names.

**KQL Query Used:**
```kql
LinuxContainer_CL
| project ContainerId, ImageName, ImageRef
| where isnotempty(ContainerId)
// returns zero rows, anywhere, confirming the field is never populated
```
`[screenshot here]`

---

### 🔐 Flag 16 & 17 – The Rejected Attempt, and the Corrective

**Objective:** Give the time and reason for the failed Nacos privilege-escalation attempt, then prove the successful retry independently from local telemetry.

**Identified Activity:**
- Failure: `19:34:36 UTC` — `POST /nacos/v1/auth/users HTTP/1.1 403 detail="blank password hash rejected"`
- Success: `19:35:07 UTC` — local `auditd` `ADD_USER` record, `pid=8801`, `uid=997`, `op=adduser id=svc_maint`

**Why It Matters:** The success is proven from **two independent** logging pipelines (the raw `Syslog` HTTP line and the local `auditd` record from the Nacos server process itself) agreeing on account name and timing — not just the agent's own self-report.

**KQL Queries Used:**
```kql
Syslog
| where Computer == "ff-nacos-01"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc

LinuxAudit_CL
| where Computer == "ff-nacos-01"
| project TimeGenerated, AuditMsg, Pid, Uid, TargetUsername, EventOriginalMessage
| order by TimeGenerated asc
```
`[screenshot here]`

---

### 🗝️ Flag 18 – The Account It Left Behind

**Objective:** Name the backdoor account.

**Identified Activity:** `svc_maint` — created inside Nacos via the forged-JWT admin session.

**Why It Matters:** Named to blend with legitimate service accounts; unlike the process-level RCE access or the IP-tied cron beacon, this is a standing, authenticated account that survives host reboots and even remediation of the original Langflow vulnerability.

**KQL Query Used:**
```kql
Syslog
| where Computer =~ "ff-nacos-01" and SyslogMessage has "adduser"
| project TimeGenerated, SyslogMessage
```
`[screenshot here]`

---

### 🔒 Flag 19 – Encryption and Destruction

**Objective:** Establish what was done to the records and how much was touched.

**Identified Activity:**
```
19:36:30  UPDATE config_info SET content=AES_ENCRYPT(content,@k)  /* 1342 rows affected */
19:36:37  DROP TABLE config_info
19:36:38  DROP TABLE history
```

**Why It Matters:** Neither `DROP TABLE` statement appears in `LinuxAudit_CL`'s `MYSQL_QUERY` records — only the raw `Syslog` query stream carries the full sequence, including a second dropped table (`history`) not mentioned in the agent's own summary.

**KQL Query Used:**
```kql
Syslog
| where Computer =~ "ff-db-01" and (SyslogMessage has "AES_ENCRYPT" or SyslogMessage has "DROP TABLE")
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```
`[screenshot here]`

---

### 💰 Flag 20 – The Ransom Note

**Objective:** Identify the table and payment address left for the victim.

**Identified Activity:**
```
CREATE TABLE README_RANSOM (msg text)
INSERT INTO README_RANSOM VALUES('Your data is encrypted. Contact e78393397@proton.me.
Pay to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')
```

**Why It Matters:** Completes the ransomware sequence, proven at the raw-query level rather than only via the agent's self-report.

**KQL Query Used:**
```kql
Syslog
| where Computer =~ "ff-db-01" and (SyslogMessage has "RANSOM" or SyslogMessage has "CREATE TABLE" or SyslogMessage has "WpEZ")
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```
`[screenshot here]`

---

### 🤖 Flag 21 – Session and Tasking

**Objective:** Isolate the conversation that does not belong to the estate's own agent traffic.

**Identified Activity:** Session `jp-7f3c9a21` (actor `jadepuffer-agent`), the only session in the table tasked with an attack objective rather than routine ops:
> *"Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions."*

**Why It Matters:** Stands apart from the estate's genuine agent traffic (`flowforge-assistant`), whose sessions carry mundane, read-scoped prompts like summarizing pipeline failures or drafting release notes.

**KQL Query Used:**
```kql
LLMAgentLogs_CL
| summarize count() by actor, session_id
```
`[screenshot here]`

---

### ⚖️ Flag 22 – The Autonomy Verdict

**Objective:** Determine whether this was human-driven, autonomous, or human-tasked.

**Verdict:** `human-tasked` — a person set the objective; the machine executed it unsupervised.

**Artifact 1** — `LLMAgentLogs_CL.user_input`: exactly one human-authored instruction across the entire 66-row/10-step session; no further human input recorded.

**Artifact 2** — `LLMAgentLogs_CL.TimeGenerated` (cross-checked against `LinuxAudit_CL.TimeGenerated`): the Nacos privilege-escalation failure-to-success cycle took **31 seconds** (diagnose a rejected request, recompute a bcrypt hash, resubmit as a multi-step payload) — a self-correction speed inconsistent with manual troubleshooting.

**KQL Query Used:**
```kql
LLMAgentLogs_CL
| where actor == "jadepuffer-agent"
| project TimeGenerated, tool_name, model_response, tool_result
| order by TimeGenerated asc
```
`[screenshot here]`

---

### 🧵 Flag 23, 24, 25 – Real or Noise (Signal Discrimination)

**Objective:** For each category of ambiguous evidence, name the field/property that separates attacker activity from routine operations.

**23. `python3.11` spawns:** field `ActingProcessName`, value `python3.11`. Benign spawns are always parented by `langflow-worker` (flow jobs) or `bash` (developer one-liners) — never by `python3.11` itself. Both attacker interpreters are `python3.11`-spawning-`python3.11`, a self-referential pattern absent from the entire legitimate baseline.

**24. External addresses:** field `DstPortNumber`, value `4444`. Every legitimate development-tool connection from this host — package registries, API calls — rides standard HTTPS on port 443. The C2 connection is the sole exception.

**25. Timing:** clustered burst, ~7 minutes. The attacker's two interpreter launches (`19:20:04`, `19:27:28`) sit as an isolated pair inside an otherwise scattered baseline — benign `python3.11` spawns occur randomly throughout the entire working day (`08:01` through `19:55`), gaps of 30 minutes to 2+ hours apart.

**KQL Queries Used:**
```kql
// 23
LinuxProcess_CL
| where DvcHostname == "ff-lf-01" and TargetProcessName =~ "python3.11"
| summarize count() by ActingProcessName

// 24
LinuxNetwork_CL
| where DvcHostname == "ff-lf-01"
| summarize count() by DstIpAddr, DstHostname, DstPortNumber, ActingProcessName
| order by DstPortNumber asc

// 25
LinuxProcess_CL
| where DvcHostname == "ff-lf-01" and TargetProcessName =~ "python3.11"
| extend tod = format_datetime(TimeGenerated, "HH:mm:ss")
| summarize by tod, ActingProcessName
| order by tod asc
```
`[screenshot here]`

---

## 🔍 Timeline of Events

| **Timestamp (UTC)** | **Event** | **Host** | **Details** |
|---|---|---|---|
| 19:20:00 | `POST /api/v1/validate/code` | ff-lf-01 | RCE request, src `64.20.53.230` |
| 19:20:04 | First interpreter spawned (PID 4471) | ff-lf-01 | `python3 -c <base64 payload>`, parent = Langflow web server |
| 19:20:05–08 | `id`, `uname -a` | ff-lf-01 | Initial recon |
| 19:22:04 | C2 beacon connection | ff-lf-01 | → `45.131.66.106:4444` |
| 19:25:04 | `pg_dump` credential harvest | ff-lf-01 | Langflow's own `variable`/`api_key` tables, 214 secrets |
| 19:25:13 | Secrets classified | ff-lf-01 | 8 provider families |
| 19:27:28 | Second interpreter spawned (PID 4491) | ff-lf-01 | Subnet sweep of `10.4.0.0/24` |
| 19:27:31–36 | Sweep connections | ff-lf-01 | MinIO, MySQL, Nacos discovered |
| 19:27:39 | MinIO default-creds probe | ff-lf-01 | `minioadmin:minioadmin` succeeds |
| 19:30:35 | Parser adjustment | ff-lf-01 | XML received, JSON expected; retried |
| 19:30:35 | `terraform-state/credentials.json` retrieved | — | Cloud credentials obtained |
| 19:33:39 | Nacos JWT forge + admin-create attempt | ff-nacos-01 | Using default signing key |
| 19:34:36 | Admin-create **rejected** | ff-nacos-01 | `403 blank password hash rejected` |
| 19:35:07 | Admin-create **succeeds** | ff-nacos-01 | `svc_maint` created, PID 8801, UID 997 |
| 19:35:18 | Forged-JWT login | ff-nacos-01 | Admin session established |
| 19:35:32 | Docker socket probed | ff-lf-01 | `GET /containers/json`; deprioritized |
| 19:35:35–19:36:00 | Persistence installed | ff-lf-01 | Cron `*/30 * * * *` → beacon, account `langflow` |
| 19:36:30 | Database encrypted | ff-db-01 | `AES_ENCRYPT`, 1,342 rows (`config_info`) |
| 19:36:37–38 | Tables dropped | ff-db-01 | `config_info`, `history` |
| 19:36:39–44 | Ransom note planted | ff-db-01 | `README_RANSOM` table created + populated |
| 19:37:00 | Chain finalized | — | Agent reports completion |

**Total elapsed time: ~17 minutes, four hosts.**

---

## 🧩 MITRE ATT&CK Mapping

| **Flag/Event** | **Tactic (TA#)** | **Technique (T#)** | **Details** |
|---|---|---|---|
| Initial RCE via `/api/v1/validate/code` | Initial Access (TA0001) | T1190 – Exploit Public-Facing Application | CVE-2025-3248, unauthenticated code validation |
| Recon (`id`, `uname`) | Discovery (TA0007) | T1082 – System Information Discovery | Immediate post-exploitation footprinting |
| `pg_dump` of Langflow secrets | Credential Access (TA0006) | T1552.001 – Credentials In Files | Targeted `variable`/`api_key` tables |
| Subnet sweep | Discovery (TA0007) | T1046 – Network Service Discovery | `10.4.0.0/24`, found MinIO/MySQL/Nacos |
| MinIO default-credential login | Initial Access (TA0001) / Lateral Movement (TA0008) | T1078.001 – Default Accounts | `minioadmin:minioadmin` unrotated |
| `terraform-state` object retrieval | Credential Access (TA0006) | T1552 – Unsecured Credentials | Cloud creds in plaintext state file |
| Nacos JWT forgery | Privilege Escalation (TA0004) | T1552 / T1556 – Modify Authentication Process | Unrotated default signing key since 2020 |
| `svc_maint` account creation | Persistence (TA0003) | T1136 – Create Account | Backdoor blending with legitimate service accounts |
| Docker socket probe | Privilege Escalation (TA0004) / Discovery | T1610 – Deploy Container / T1613 – Container Discovery | Deprioritized in favor of primary objective |
| Cron beacon persistence | Persistence (TA0003), Command and Control (TA0011) | T1053.003 – Scheduled Task/Job: Cron; T1071 – Application Layer Protocol | `*/30 * * * *` → `curl \| python3 -` |
| C2 connection to `45.131.66.106:4444` | Command and Control (TA0011) | T1071 / T1571 – Non-Standard Port | Reverse-shell-style callback |
| MySQL `AES_ENCRYPT` + `DROP TABLE` | Impact (TA0040) | T1486 – Data Encrypted for Impact | 1,342 rows, `config_info` + `history` dropped |
| Ransom note (`README_RANSOM`) | Impact (TA0040) | T1657 – Financial Theft | BTC address planted for payment |
| Autonomous agent execution | (Meta) | — | Single human tasking prompt; all execution machine-driven |

---

## 💠 Diamond Model Summary

| **Feature** | **Details** |
|---|---|
| **Adversary** | An autonomous LLM agent (`jadepuffer-agent`), tasked by a single human-authored instruction, operating without further human input; demonstrated self-correction on failure (Nacos admin-create) and adaptive tooling (parser rewrite on unexpected XML). |
| **Infrastructure** | External RCE source `64.20.53.230`; C2/reverse-shell listener `45.131.66.106:4444`; internal pivot points `10.4.0.20` (MinIO), `10.4.0.30` (MySQL/ff-db-01), `10.4.0.40` (Nacos). |
| **Capability** | Known-CVE exploitation (CVE-2025-3248), credential harvesting via `pg_dump`, default-credential abuse (MinIO), JWT forgery against an unrotated signing key (Nacos), cron-based persistence, MySQL `AES_ENCRYPT`-based ransomware. |
| **Victim** | Flowforge's four-host Linux estate: `ff-lf-01` (Langflow, entry point), `ff-minio-01`, `ff-nacos-01` (privilege escalation, backdoor account), `ff-db-01` (ransomware target — Nacos's backing MySQL). |

---

## 💡 Key Relationships

- Adversary used **capability** (RCE, credential dump, default creds, JWT forgery, ransomware) against **victim** (all four Flowforge hosts) via **infrastructure** (staging IP for delivery, C2 IP for the beacon).
- Each stage's credentials directly enabled the next: Langflow secrets → MinIO access was independent (default creds), but MinIO's `terraform-state` object directly enabled the Nacos pivot.
- A single human **tasking instruction** activated the entire capability chain — the agent's own reasoning log is the evidentiary link between intent and outcome.

---

## ✅ Conclusion

This hunt reconstructed the first fully agent-driven ransomware operation observed in this environment: a single human-issued objective (*"gain access, encrypt the most business-critical datastore, leave payment instructions"*) triggered an autonomous LLM agent that independently discovered a known Langflow RCE, harvested credentials, pivoted through three internal services using a mix of default credentials and forged authentication, and delivered ransomware against the Nacos-backing MySQL database — all in under 20 minutes, with no further human direction. The investigation repeatedly required correlating facts split across the custom `Linux*_CL` telemetry tables and the native `Syslog` table; several key artifacts (the exploit's source IP, the literal `DROP TABLE` statements, the ransom-note SQL) existed only in `Syslog`, not in the tables that seemed most obviously relevant. One flag — the specific containers seen during the Docker-socket probe — was correctly identified as unanswerable given a structural gap in the container-runtime log source, rather than forced to a fabricated answer.

---

## 🧠 Lessons Learned

- **Agentic threats execute and adapt at machine speed.** The Nacos privilege-escalation failure was diagnosed, fixed, and successfully retried in 31 seconds — no human-paced troubleshooting could match that cadence.
- **Default credentials remain the single easiest way in.** MinIO's unrotated `minioadmin:minioadmin` and Nacos's unrotated 2020-era JWT signing key were both walked through without any exploit.
- **Split telemetry hides ground truth.** Multiple critical facts (source IP, `DROP TABLE` statements, ransom SQL) existed only in `Syslog`, invisible to anyone stopping at the custom `_CL` tables.
- **Absent fields are not evidence.** An empty `SHA256` or empty `ContainerId` field, checked only against the suspicious activity, looks like a meaningful signal — checked against the *entire* dataset, both turned out to be structural gaps in the logging pipeline, not indicators of anything.
- **Infrastructure secrets in object storage are a standing risk.** `terraform-state/credentials.json` in a MinIO bucket handed the agent a path to full internal privilege escalation.
- **A single tasking prompt can trigger a full kill chain.** No further human interaction was required or recorded after the initial instruction — the operational bottleneck is not attacker effort, but attacker intent.

---

## 🛡 Remedial Actions

1. **Patch and constrain Langflow**
   - Apply the CVE-2025-3248 fix / upgrade Langflow past the vulnerable version
   - Do not expose Langflow's API directly to any untrusted network; require authentication in front of it

2. **Rotate and audit default credentials**
   - Change MinIO's default `minioadmin` credentials immediately; audit all deployed instances for factory defaults
   - Rotate Nacos's JWT signing key and enforce periodic rotation going forward

3. **Restrict object-store contents**
   - Never store Terraform state files (or any file containing live credentials) in a generally-reachable bucket; use a dedicated, tightly-scoped backend with encryption and access logging

4. **Harden persistence surfaces**
   - Alert on cron entries written by service accounts, especially those piping `curl | python3` or equivalent
   - Monitor for `ADD_USER` audit events on internal services (Nacos, etc.) outside change-managed windows

5. **Detect self-spawning interpreters**
   - Alert when a process's parent shares its own binary/image identity (e.g., `python3.11` spawning `python3.11`) outside known legitimate wrapper patterns

6. **Flag non-standard outbound ports**
   - Alert on any outbound connection to ports outside an allow-list (443/8443 for this estate) from application hosts

7. **Close the fileless-detection gap**
   - Enable and verify file-hash capture in the Sysmon-for-Linux (or equivalent) configuration; an environment where hashing is silently disabled cannot distinguish fileless execution from ordinary activity

8. **Close the container-visibility gap**
   - Configure the container runtime logging pipeline to capture response content (container IDs/images), not just request metadata, so a Docker-socket probe's actual exposure can be assessed
