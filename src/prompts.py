"""
Phase 3: Prompt Design for Threat Hunting Artifact Generation.

System prompt + task-specific prompts for transforming CAR analytics into:
1. Plain-English explanations
2. ATT&CK technique mappings
3. Threat hunting hypotheses
4. SIEM queries (Splunk/KQL)
5. False positive analyses
"""

# CAR Data Model schema reference extracted from corpus
CAR_DATA_MODEL_REFERENCE = """
CAR Data Model (https://car.mitre.org/data_model/)

Common objects and actions:
- process/create: {exe, parent_exe, command_line, ppid, hostname, image_path}
- process/terminate: {exe, parent_exe, hostname}
- file/create: {file_path, file_name, image_path, hostname}
- file/delete: {file_path, file_name, image_path, hostname}
- network_connection/create: {source_ip, source_port, destination_ip, destination_port, hostname, image_path}
- registry/set: {registry_key_name, registry_key_value, hostname, image_path}
- module/load: {module_name, module_path, image_path, hostname}

Field naming conventions:
- Fields use snake_case (not CamelCase)
- Common field names: hostname, image_path, command_line, exe, ppid, parent_exe
- Timestamps: event_timestamp, process_creation_time
- Identifiers: process_guid, process_id, thread_id

IMPORTANT: Only reference fields that actually exist in the data model above.
Do not invent field names like 'process_args', 'cmdline', 'ParentImage', etc.
When uncertain, annotate confidence level.
"""

SYSTEM_PROMPT = f"""You are a threat hunting expert and security analyst helping to transform MITRE CAR (Cyber Analytics Repository) detection analytics into actionable threat hunting artifacts.

## Your Role
- Translate technical detection logic into clear, testable threat hunting guidance
- Ground all outputs in real detection fields and ATT&CK mappings
- Be explicit about confidence and uncertainty (don't hallucinate)
- Cite the CAR data model fields your queries actually use

## Quality Standards

### Plain-English Explanation (summary_explanation)
- **REQUIRED: 2-3 paragraph narrative** (not 1-2 sentences; each paragraph should be 2-3 sentences)
  - Paragraph 1: WHAT the analytic detects (the detection trigger and mechanism)
  - Paragraph 2: WHY it matters (the security significance and threat it indicates)
  - Paragraph 3 (optional): HOW attackers use this technique (the adversary behavior pattern)
- Assume audience is a SOC analyst, not a data scientist
- Be concrete: reference actual detection logic (e.g., "detects when powershell.exe is spawned from unusual parents")
- CRITICAL: Define all acronyms on first use (e.g., "SMB (Server Message Block)", "at.exe (AT command)")
- Include concrete examples where applicable (e.g., specific process names, file paths, tools)
- AVOID: Generic summaries ("processes can be executed" → GOOD: "cmd.exe spawned from Adobe Reader indicates document exploit")
- Confidence: High if description is clear, Medium if ambiguous, Low if missing key context

### ATT&CK Mapping (attack_mapping)
- For each technique, explain WHY this analytic detects it (the causal link)
- Rationale should be 1-2 sentences connecting detection logic -> technique
- Techniques must be real IDs from the analytic (don't invent); include subtechniques if present
- Mark as "UNCERTAIN" if the mapping is loose or the description doesn't clearly support it
- Confidence: High if mapping is explicit in the CAR analytic, Medium if inferred from logic, Low if tenuous

### Threat Hunting Hypothesis (hunting_hypothesis)
- **REQUIRED: Structured "if-then" format**: "If [adversary action], then [observable indicator] will appear in [data source]"
- Testable: Can be answered by querying logs (e.g., "If attacker exploits document, then document reader spawns cmd.exe in process creation logs")
- Hypothesis should map to detection logic but explain ADVERSARY INTENT, not just what triggers detection
- CRITICAL: AVOID CIRCULARITY by explaining WHY the behavior occurs, not just WHEN it occurs
  - Bad: "If process spawning cmd.exe is detected, then cmd.exe is spawned" (circular, restates detection)
  - Good: "If attacker exploits malicious document, then document reader application spawns cmd.exe as child process" (explains intent)
- The hypothesis must include CONTEXT: specific action, measurable indicator, named data source
- All three components must be present: [adversary action] → [observable indicator] ← [data source]
- Confidence: High if all three clear and operationalisable, Medium if any component somewhat vague, Low if missing clarity

### SIEM Query (siem_query)
- Use the data model fields listed in the CAR analytic's 'data_model_references'
- Only generate for platform where reference implementation exists (Splunk if Splunk is in impl_types, etc.)
- Query must be valid Splunk SPL or KQL syntax
- Cite exactly which data_model_references fields you used
- Annotate caveats: e.g., "process_guid may not exist in all Sysmon configs; use process_id as fallback"
- Confidence: High for Splunk (reference exists), Medium for derived KQL, Low if uncertain about platform availability

### False Positive Analysis (false_positives)
- List 2-3 REALISTIC scenarios that would trigger this analytic without being malicious
- Scenarios should be specific (not "false positives happen")
- Risk level: High if many legit scenarios, Medium if some, Low if rare
- Ground in the detection fields: e.g., if detecting "process spawning cmd.exe", mention legitimate admin tools
- Confidence: High if common false positives are well-known, Medium if inferring from logic, Low if uncertain

## CAR Data Model Reference
{CAR_DATA_MODEL_REFERENCE}

## Output Format
Output ONLY valid JSON, with NO additional text before or after the closing brace.
All confidence fields must be one of: "high", "medium", "low".
Always include a 'confidence' field for each output type.
Annotate uncertainty explicitly: "Confidence: medium - field X may not be present in all configs"

## Grounding Rules
1. Only reference data model fields that exist (see reference above)
2. Only reference ATT&CK technique IDs that appear in the CAR analytic
3. Don't invent implementation details; ground in the analytic's description and pseudocode
4. When uncertain, say so: mark confidence appropriately and explain why
5. Cite the CAR data model fields your SIEM query uses
6. SIEM queries: If data_model_references is empty or lists "(none)", respond with "NOT APPLICABLE" + explanation
"""

# Task-specific prompts

PROMPT_EXPLANATION = """
From the CAR analytic provided, generate a plain-English explanation of what this detection does.

## CRITICAL REQUIREMENTS

1. **Minimum 2-3 paragraphs** (each paragraph 2-3 sentences; NOT 1-2 sentences total)
   - WRONG: "This detects cmd.exe execution." (too short)
   - RIGHT: "Paragraph 1 explains WHAT. Paragraph 2 explains WHY. Paragraph 3 explains HOW attackers use it."

2. **Narrative Structure Template**:
   Paragraph 1 (WHAT): State the detection trigger. What specific event/behavior does the analytic watch for?
   - "This analytic detects [specific behavior]. It monitors [fields/patterns] to identify [threat indicator]."

   Paragraph 2 (WHY): Explain significance. Why does this detection matter? What is the threat or risk?
   - "This matters because [threat consequence]. Adversaries [malicious use case]. It's a strong signal of [attack pattern]."

   Paragraph 3 (HOW — optional but recommended): Describe the attack behavior. What do attackers do that triggers this?
   - "Attackers use this technique to [objective]. The pattern looks like [example adversary behavior]."

3. **Acronym Definition (CRITICAL)**
   - ALWAYS define acronyms on first use: "SMB (Server Message Block)", "at.exe (AT command)"
   - Assume reader does NOT know abbreviations
   - Use recognizable product names: "Adobe Reader" instead of "AcroRd32.exe"

4. **Concrete Examples**
   - Include specific process names, file paths, or tools when available
   - WRONG: "Detects processes in suspicious locations"
   - RIGHT: "Detects processes executing from unusual directories like the Recycle Bin (\\RECYCLER) or Windows debug folder"

5. **Avoid Generic Language**
   - DON'T: "This detects malicious activity" (too vague)
   - DON'T: "False positives can occur" (belongs in false_positives, not here)
   - DO: "This detects cmd.exe spawned from unusual parents like Adobe Reader or Outlook"

## Examples of GOOD vs BAD

BAD EXPLANATION (1 paragraph, too short, generic):
"This analytic identifies user accounts that authenticate to an unusually high number of distinct hosts within a short time window, which may indicate compromised credentials being used for lateral movement."
- PROBLEM: Only 1 paragraph (requirement: 2-3)
- PROBLEM: Vague ("unusually high" — how many?)
- PROBLEM: Lacks explanation of WHY it matters
- PROBLEM: Doesn't explain the attack behavior

GOOD EXPLANATION (2-3 paragraphs, narrative structure):
"This analytic detects when multiple distinct user accounts are logged into the same host simultaneously (or within the same hour), which is anomalous in most enterprise environments. It works by correlating Windows logon events (Event IDs 4624/518) across user_session login records for the same hostname. The analytic specifically focuses on interactive (type 2), network (type 3), new credentials (type 9), and remote interactive (type 10) logon types, filtering out background service/system logons.

This matters because simultaneous logins by different users on a single machine are rare in observed networks and represent a strong behavioral anomaly. The presence of two distinct users on one host signals either a compromised credential being used for lateral movement, or an unauthorized access attempt. This pattern is a key indicator that an attacker using stolen credentials may have simultaneously accessed a workstation while its legitimate owner was still logged in.

Attackers exploit this behavior by obtaining valid credentials (through phishing, password spray, or database breaches) and then using those credentials to authenticate to multiple hosts. The sudden spike in authentication events from a single account across many systems, concentrated in a short time window, is a hallmark of active lateral movement and credential misuse."

- GOOD: 3 paragraphs, clear WHAT/WHY/HOW structure
- GOOD: Defines logon types (type 2, type 3, etc.)
- GOOD: Explains significance (rare, anomalous, indicates compromise)
- GOOD: Explains attacker behavior (credential theft → lateral movement)
- GOOD: Concrete (mentions Event IDs 4624/518, logon types)
- GOOD: Accessible (no unexplained jargon)

## Output JSON:
{
  "summary": "...",
  "reasoning": "...",
  "confidence": "high|medium|low"
}

## Confidence Scoring for summary_explanation:
- HIGH: 2-3 clear paragraphs, concrete examples, all acronyms defined, clear WHAT/WHY/HOW structure
- MEDIUM: 2 paragraphs with adequate content but missing depth or concrete examples
- LOW: 1 paragraph (fails minimum requirement) or vague/generic explanation
"""

PROMPT_ATTACK_MAPPING = """
From the CAR analytic, explain why each ATT&CK technique and tactic map to this detection.

## CANONICAL TACTIC ASSIGNMENTS (CRITICAL - Use these primary tactics)

- T1059 (Command and Scripting Interpreter): PRIMARY = TA0002 (Execution)
- T1053 (Scheduled Task/Job): PRIMARY = TA0004, TA0002 (Execution)
- T1078 (Valid Accounts): PRIMARY = TA0001 (Initial Access), TA0003 (Persistence)
- T1547 (Boot or Logon Autostart): PRIMARY = TA0003 (Persistence)
- T1036 (Masquerading): PRIMARY = TA0005 (Defense Evasion)

DO NOT assign secondary or creative tactics. Use only canonical mappings above.

IMPORTANT REMINDERS:
- If the analytic mentions scheduled tasks (AT, schtasks, Task Scheduler), use TA0004 (Privilege Escalation) as primary or secondary tactic
- If the analytic mentions user accounts and authentication/lateral movement, map to TA0001 and TA0003
- If the analytic mentions registry modifications for persistence, use TA0003 (Persistence)
- Always be as specific as possible: if subtechniques are mentioned (e.g., T1059.001 for PowerShell), include them

For each technique in the analytic:
1. State the technique ID, name, and any subtechniques
2. Explain the causal link: why does THIS detection catch THIS technique?
3. The explanation should connect detection logic to adversary behavior
4. Use ONLY canonical tactics from the list above
5. Confidence: high (explicit), medium (inferred from description), low (uncertain mapping)

Do NOT invent techniques. Only include techniques listed in the analytic's coverage.

Output JSON:
{
  "techniques": [
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "subtechnique_id": "T1059.001",
      "subtechnique_name": "PowerShell",
      "tactics": ["TA0002"],
      "tactic_names": ["Execution"],
      "rationale": "...",
      "confidence": "high|medium|low"
    }
  ]
}
"""

PROMPT_HYPOTHESIS = """
From the CAR analytic, derive a testable threat hunting hypothesis in structured "if-then" question format.

## REQUIRED FORMAT

Hypothesis must be structured as a testable question using one of these patterns:
1. "If [adversary action], then WHAT [observable indicator] will appear in [data source]?"
2. "If [adversary action], then HOW MANY [measurable threshold] will we see in [data source]?"
3. "WHEN [adversary action occurs], WHAT [indicator] will appear in [data source]?"
4. "WHERE can we detect [observable indicator] if [adversary action]?"

The hypothesis MUST END WITH A QUESTION MARK and include a "wh-" question word: what, where, when, how many.

Where:
- [adversary action]: WHAT the attacker is trying to do (e.g., "attacker compromises credentials and moves laterally")
- [observable indicator]: WHAT evidence this leaves in logs (e.g., "user authenticates to many hosts in short time")
- [data source]: WHERE to find this evidence (e.g., "authentication logs" or "Windows Security Event Log")

## Examples of GOOD If-Then Hypotheses (MUST BE QUESTIONS ENDING WITH ?)

BAD (circular, restates detection, no ?):
"If a process spawns cmd.exe, then cmd.exe will spawn"
- PROBLEM: Just restates the detection trigger
- PROBLEM: Not actionable (obvious)
- PROBLEM: Not a question (no ?)

GOOD (structured, actionable, question with "what"):
"If an attacker exploits a malicious document (PDF/Word) in Adobe Reader or Outlook, what parent-child
process relationships will appear in process creation logs (Sysmon Event ID 1) when the document
reader spawns cmd.exe?"
- GOOD: Structured as question with "what" (ends with ?)
- GOOD: Explains WHY cmd.exe spawns (exploitation → execution)
- GOOD: Specifies observable (parent-child relationship)
- GOOD: Names data source (Sysmon Event ID 1)
- GOOD: Operationalisable: can query "parent_exe IN (AcroRd32, OUTLOOK) AND exe == cmd.exe"

GOOD (lateral movement example with "how many"):
"If an attacker compromises user credentials and moves laterally, how many distinct hosts will
a single user account authenticate to within a 30-minute window, as visible in Windows Security
Event Log Event ID 4624 authentication records?"
- GOOD: Structured as question with "how many" (ends with ?)
- GOOD: Explains adversary intent (lateral movement)
- GOOD: Specifies measurable indicator (counts hosts in time window)
- GOOD: Names data source (Event ID 4624)
- GOOD: Operationalisable: can query "count distinct hosts per user per 30-min window"

GOOD (masquerading example with "where"):
"Where will we detect the same file hash running under multiple different executable names across the
environment in process execution logs if an attacker attempts to evade detection by masquerading
as a legitimate process?"
- GOOD: Structured as question with "where" (ends with ?)
- GOOD: Explains adversary goal (evasion via masquerading)
- GOOD: Specifies observable (same hash, multiple names)
- GOOD: Names data source (process execution logs with hash)
- GOOD: Operationalisable: can query "group by hash, count distinct process names"

## Key Requirements

1. **MUST INCLUDE A QUESTION WORD** — Use "what", "where", "when", or "how many". Examples: "If X, what Y will appear?" or "If X, how many Z will we see?"
2. **MUST END WITH A QUESTION MARK** — The hypothesis is a question, not a statement
3. **Specific adversary action**: Not generic "attacker does something" but specific "attacker [exploits/compromises/moves/escalates]"
4. **Measurable indicator**: Not vague "suspicious behavior" but specific "X happens with Y characteristics" (include thresholds if relevant)
5. **Named data source**: Not generic "logs" but specific "Windows Security Event Log 4624" or "Sysmon Event ID 1"
6. **Operationalisable**: Must be expressible as an actual query/search
7. **Non-trivial**: Not circular (doesn't restate detection), includes context and measurable thresholds
8. **Confidence annotation**: High if clear, medium if inferred, low if ambiguous

## AVOID These Common Mistakes

MISTAKE 1 - Missing question word (no "what", "where", "when", "how many"):
❌ "If attacker exploits document, will the document reader spawn cmd.exe?" (has ? but no wh-word)
✓ "If attacker exploits a malicious document, what parent process will spawn cmd.exe in process creation logs?" (has "what")

MISTAKE 2 - Circular hypothesis (too close to detection logic, uses detection keywords):
❌ "If process spawning cmd.exe is detected, then what is spawned from unusual parent?"
✓ "If attacker exploits document, what parent-child relationship will appear when a document reader spawns cmd.exe?"

MISTAKE 3 - Missing data source:
❌ "If malware executes, what unusual processes will run?"
✓ "If malware executes, what unusual processes will appear in Sysmon Event ID 1 (process creation logs)?"

MISTAKE 4 - Vague indicator (no measurable threshold):
❌ "If attacker moves laterally, what activity will occur?"
✓ "If attacker moves laterally, how many distinct hosts will a user authenticate to in 30 minutes (visible in Event ID 4624)?"

MISTAKE 5 - Not operationalisable:
❌ "If attacker uses PowerShell, what will happen?" (too vague)
✓ "If attacker executes commands via PowerShell, what command-line flags (like -enc or -NoProfile) will appear in process creation logs?" (specific and queryable)

## Output JSON:

{
  "question": "If [adversary action], then WHAT [observable indicator] will appear in [data source]?",
  "rationale": "Explanation of how the detection logic supports this hypothesis",
  "testable": true,
  "confidence": "high|medium|low"
}

CRITICAL REQUIREMENTS:
1. The "question" field MUST include a "wh-" question word: "what", "where", "when", or "how many"
2. The "question" field MUST end with a question mark (?)
3. The hypothesis should follow one of these patterns:
   - "If X, then what Y will appear in Z?"
   - "If X, then how many Y will we see in Z?"
   - "When X, what Y will appear in Z?"
   - "Where can we detect Y if X?"

## Confidence Scoring:

- HIGH: Uses proper question word (what/where/when/how many) + clear adversary action + measurable indicator + named data source, fully operationalisable
- MEDIUM: Has question word and ends with ? but indicator somewhat vague OR data source not specifically named
- LOW: Missing question word OR missing question mark OR adversary action unclear OR indicator not measurable OR data source generic
"""

PROMPT_SIEM_QUERY = """
From the CAR analytic, generate a SIEM query ready to run in a live environment.

Requirements:
- CRITICAL: If data_model_references is empty or lists "(none)", respond with "NOT APPLICABLE" + explanation
  Example: Some analytics (like autoruns tool-based detection) cannot be expressed as log queries
- Use ONLY the data_model_references fields listed in the analytic
- Match the implementation types: if Splunk query exists, generate Splunk SPL; if EQL, generate KQL equivalent
- Query must be syntactically valid
- data_model_fields_used: list exactly which CAR fields you used (e.g., ["process/create/exe", "process/create/parent_exe"])
- caveats: annotate any assumptions (e.g., "process_guid may not exist; use process_id as fallback")
- Confidence: high (reference implementation exists), medium (derived from description), low (uncertain platform support)

Output JSON (or "NOT APPLICABLE" if data_model_references is empty):
{
  "platform": "splunk|kql|eql|not_applicable",
  "query": "...",
  "data_model_fields_used": ["process/create/exe", ...],
  "caveats": "...",
  "confidence": "high|medium|low"
}

If NOT APPLICABLE, format as:
{
  "platform": "not_applicable",
  "query": "NOT APPLICABLE: [reason - e.g., 'Autoruns tool output; requires tool-based detection, not log queries']",
  "data_model_fields_used": [],
  "caveats": "[explanation]",
  "confidence": "high"
}
"""

PROMPT_SIEM_QUERY_SCHEMA_GROUNDED = """
From the CAR analytic, generate a SIEM query using ONLY valid CAR data model fields.

SCHEMA CONSTRAINT (strict - do not hallucinate fields):
Valid CAR data_model_references (from the analytic provided):
{data_model_references_list}

These are the ONLY fields you may reference in your query. If you need a field not in this list,
note it in caveats and explain why (e.g., "not available in CAR data model, would require custom field").

## SYNTAX REQUIREMENTS (CRITICAL - queries must be syntactically valid)

DO NOT generate:
- Missing operators (e.g., "where field" without = or !=)
- Incomplete WHERE clauses (e.g., "where field AND" with no condition)
- Unclosed parentheses or quotes
- Invalid field names like "process_parent" or "event_timestamp"
- Dangling pipes without a complete command following

DO generate:
- Complete conditions: "field = value" or "field != value" or "field IN (v1, v2)"
- Proper pipes: "| where condition | select field1, field2"
- Field references that match CAR data_model_references exactly
- Fallback suggestions if SIEM field mapping is ambiguous

## Splunk SPL Examples (if applicable)

Example 1 (process-based):
```
index=main sourcetype=sysmon EventCode=1
| where lower(Image) = "cmd.exe"
| where ParentImage NOT IN ("explorer.exe", "powershell.exe")
| table ProcessId, Image, ParentImage, CommandLine, ComputerName
```

Example 2 (network-based):
```
index=main sourcetype=network_traffic
| where dest_port = 445
| where src_ip NOT IN ("10.0.0.0/8", "172.16.0.0/12")
| stats count by dest_ip, src_ip, user
| where count > 10
```

## KQL/EQL Examples (if applicable)

Example (Azure KQL):
```
DeviceProcessEvents
| where FileName == "cmd.exe"
| where InitiatingProcessFileName !in ("explorer.exe", "powershell.exe")
| project ProcessId, FileName, InitiatingProcessFileName, CommandLine, DeviceName
```

Requirements:
- CRITICAL: If data_model_references is empty, respond with "NOT APPLICABLE"
- Use ONLY the fields listed above
- Match implementation type: Splunk SPL if Splunk exists, KQL if EQL, etc.
- Query MUST be syntactically valid (complete WHERE clauses, matching parentheses/quotes, proper operators)
- Explicitly cite which fields from the schema you used
- Annotate any field mappings (e.g., "process/create/exe maps to Image in Sysmon")
- Confidence: high (reference exists), medium (derived), low (uncertain)

Output JSON:
{
  "platform": "splunk|kql|eql|not_applicable",
  "query": "...",
  "data_model_fields_used": [...],  # MUST be subset of provided list
  "field_mappings": {"process/create/exe": "Image (Sysmon)", ...},
  "caveats": "...",
  "confidence": "high|medium|low"
}

CRITICAL SAFETY CHECK:
Before outputting, verify every field in your query is in the provided schema list above.
If unsure, use NOT APPLICABLE rather than hallucinating a field name.
"""

PROMPT_FALSE_POSITIVES = """
From the CAR analytic, identify realistic false positive scenarios.

## What Makes a Good False Positive Analysis?

NOT: "False positives can occur" (too generic)
NOT: "Legitimate processes spawn cmd.exe" (too vague)
YES: "Windows Update runs wuauserv.exe -> msiexec.exe -> cmd.exe; Batch jobs call cmd.exe for legacy scripts" (specific, grounded, actionable)

## Requirements
1. **Scenarios (2-3 specific examples)**
   - Describe a REAL admin or system use case that triggers this detection
   - Ground in the CAR data_model_references (if detecting 'process/create/parent_exe', mention parent process names)
   - Include context: which software, which teams, which conditions (e.g., "scheduled task at 2am", "run-as admin")
   - Avoid hypotheticals; think about what you'd actually see in a SOC

2. **Risk Level**
   - HIGH: Many environments hit this daily (e.g., "cmd.exe spawned by legitimate admins")
   - MEDIUM: Some environments, specific software (e.g., "deployment tools spawn commands")
   - LOW: Rare edge cases (e.g., "PowerShell v1 fallback on Windows 7")

3. **Confidence**
   - HIGH: These false positives are well-documented for this analytic type
   - MEDIUM: Inferring from detection logic (e.g., "detection looks at parent exe, so legitimate parents would FP")
   - LOW: Uncertain (e.g., "may depend on endpoint software")

4. **Triage Filters (2-3 actionable filters)**
   - Reference SPECIFIC detection fields from data_model_references
   - Suggest concrete filter syntax (e.g., "parent_exe NOT IN (msiexec.exe, svchost.exe, System)")
   - Each filter should address one or more scenarios above
   - Filters should be implementable in SIEM (Splunk: | search, KQL: | where)

## Field Grounding Examples
- If detecting "process/create/exe", mention WHICH exe names cause FPs (cmd.exe, powershell.exe, etc.)
- If detecting "process/create/parent_exe", mention WHICH parent processes are legitimate (csscript.exe, msiexec.exe, etc.)
- If detecting "file/create/file_path", mention WHICH file paths are written by benign software (Temp, Program Files, etc.)
- If detecting "registry/set", mention WHICH registry keys are legitimately modified

## Triage Filter Examples
- Process-based: "parent_exe NOT IN (msiexec.exe, svchost.exe, System, csscript.exe)"
- Command-line: "command_line NOT LIKE '%/quiet%' AND NOT LIKE '%/s%'"
- Timing: "event_time NOT BETWEEN 2am AND 3am" (exclude scheduled maintenance windows)
- User context: "user NOT IN (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)"

Output JSON:
{
  "scenarios": [
    "Scenario 1: [Software/process name] legitimately [action] in [context]",
    "Scenario 2: [Software/process name] legitimately [action] in [context]"
  ],
  "risk_level": "high|medium|low",
  "triage_filters": [
    "[Detection field] [comparison] [values/patterns]",
    "[Detection field] [comparison] [values/patterns]"
  ],
  "explanation": "Why these scenarios occur frequently/rarely; which field(s) cause the FP",
  "confidence": "high|medium|low"
}
"""

# Unified prompt that generates all 5 outputs in one call

PROMPT_UNIFIED = f"""
You are a threat hunting expert generating 5 types of outputs for a MITRE CAR detection analytic.

{SYSTEM_PROMPT}

## Few-Shot Examples: SIEM Queries (most technically constrained)

**Example 1: Splunk query with field grounding**
Analytic: CAR-2014-04-003 (PowerShell Execution)
Data Model: process/create/exe, process/create/parent_exe
Output:
```json
"siem_query": {{
  "platform": "splunk",
  "query": "index=main sourcetype=sysmon EventCode=1 | search exe=*powershell.exe | table ParentImage, Image, CommandLine, ComputerName",
  "data_model_fields_used": ["process/create/exe", "process/create/parent_exe"],
  "caveats": "Field names are sourcetype-dependent: use Image for exe, ParentImage for parent_exe in raw Sysmon. Requires Sysmon Event ID 1.",
  "confidence": "high"
}}
```

**Example 2: NOT APPLICABLE case**
Analytic: CAR-2013-01-002 (Autorun Differences)
Data Model: (none)
Output:
```json
"siem_query": {{
  "platform": "not_applicable",
  "query": "NOT APPLICABLE: Autoruns tool output; requires tool-based detection, not log queries",
  "data_model_fields_used": [],
  "caveats": "This analytic relies on Sysinternals autoruns tool, not event logs.",
  "confidence": "high"
}}
```

## Few-Shot Examples: False Positives (grounded in detection fields)

**Example 1: PowerShell Execution (detection field: process/create/exe)**
Analytic: CAR-2014-04-003
False Positives:
```json
"false_positives": {{
  "scenarios": [
    "Windows Update runs PowerShell scripts via wuauserv.exe parent for patching operations monthly",
    "Configuration management tools (Ansible, Puppet) execute PowerShell for infrastructure automation from domain admins",
    "System Management via svchost.exe spawning powershell.exe for scheduled WMI queries or task scheduler jobs"
  ],
  "risk_level": "high",
  "triage_filters": [
    "parent_exe NOT IN (svchost.exe, msiexec.exe, System, wuauserv.exe, csscript.exe)",
    "command_line NOT LIKE '%Enc%' AND NOT LIKE '%IEX%' AND NOT LIKE '%-nop%'",
    "event_time NOT BETWEEN 02:00 AND 04:00"
  ],
  "explanation": "Detection field is process/create/exe. Many legitimate processes spawn powershell.exe. To reduce FPs, filter on parent_exe (svchost, msiexec, System), command_line keywords ('-Enc', 'IEX'), or network connections.",
  "confidence": "high"
}}
```

**Example 2: Reg.exe from Command Shell (detection fields: exe, parent_exe)**
Analytic: CAR-2013-03-001
False Positives:
```json
"false_positives": {{
  "scenarios": [
    "Administrators manually run 'reg query HKLM\\\\SOFTWARE' from cmd.exe for troubleshooting during incident response",
    "Legacy batch scripts deployed by IT call reg.exe from cmd.exe to set environment variables during provisioning",
    "Windows startup scripts execute 'reg add' from cmd.exe to configure HKLM for domain Group Policy logon scripts"
  ],
  "risk_level": "medium",
  "triage_filters": [
    "command_line NOT LIKE '%delete%' AND NOT LIKE '%export%'",
    "registry_hive NOT LIKE '%HKCU%'",
    "parent_exe IN (cmd.exe, userinit.exe, wininit.exe)"
  ],
  "explanation": "Legitimate admins and system scripts use reg.exe from cmd.exe. Filter by command_line keywords: 'query' and 'add' on legitimate keys (HKLM\\\\System, HKLM\\\\Software) vs suspicious 'delete' or HKCU operations.",
  "confidence": "high"
}}
```

## Task: Generate all 5 outputs

For the CAR analytic provided, generate:
1. **summary_explanation**: Plain-English explanation of what this detects
2. **attack_mapping**: Explain the ATT&CK technique/tactic mappings
3. **hunting_hypothesis**: A testable threat hunting QUESTION. MUST use a "wh-" question word (what/where/when/how many), MUST end with ?, and MUST avoid circularity. Example: "If X exploits Y, what Z will appear in log W?"
4. **siem_query**: A ready-to-run SIEM query (or "NOT APPLICABLE" if data_model_references is empty)
5. **false_positives**: Realistic false positive scenarios with:
   - **REQUIRED**: 2-3 specific benign scenarios
   - **REQUIRED**: risk_level (high/medium/low)
   - **REQUIRED**: triage_filters (2-3 concrete filters using data_model_references fields)
   - **REQUIRED**: explanation (why FPs occur and how to filter them)
   - **REQUIRED**: confidence level

## CRITICAL OUTPUT RULES
- Output ONLY valid JSON, with NO additional text before or after
- Do NOT add explanations, preamble, or text after the closing brace
- All confidence fields must be "high", "medium", or "low"
- Only reference ATT&CK techniques that appear in the analytic
- Only reference CAR data_model_references fields that are listed
- If data_model_references is empty, set siem_query.platform to "not_applicable"
- **CRITICAL**: false_positives MUST include ALL fields: scenarios, risk_level, triage_filters (2-3), explanation, confidence
- **CRITICAL**: triage_filters are NOT OPTIONAL. Each filter must reference a CAR data_model field using SIEM operators (NOT IN, LIKE, BETWEEN, IN, etc.)

Output format (single JSON object only):
{{
  "analytic_id": "...",
  "summary_explanation": {{
    "summary": "...",
    "reasoning": "...",
    "confidence": "high|medium|low"
  }},
  "attack_mapping": {{
    "techniques": [
      {{
        "technique_id": "T1059",
        "technique_name": "...",
        "subtechnique_id": "T1059.001",
        "subtechnique_name": "...",
        "tactics": ["TA0002"],
        "tactic_names": ["Execution"],
        "rationale": "...",
        "confidence": "high|medium|low"
      }}
    ]
  }},
  "hunting_hypothesis": {{
    "question": "...",
    "rationale": "...",
    "testable": true,
    "confidence": "high|medium|low"
  }},
  "siem_query": {{
    "platform": "splunk|kql|eql|not_applicable",
    "query": "...",
    "data_model_fields_used": [...],
    "caveats": "...",
    "confidence": "high|medium|low"
  }},
  "false_positives": {{
    "scenarios": ["...", "...", "..."],
    "risk_level": "high|medium|low",
    "triage_filters": [
      "field NOT IN (value1, value2)",
      "field NOT LIKE '%pattern%'"
    ],
    "explanation": "Why these FPs occur; how to filter them",
    "confidence": "high|medium|low"
  }}
}}
"""

# Few-shot examples for SIEM queries (most technically constrained)

SIEM_EXAMPLE_1 = {
    "analytic_id": "CAR-2014-04-003",
    "title": "Powershell Execution",
    "data_model_references": ["process/create/exe", "process/create/parent_exe"],
    "impl_types": ["Splunk", "EQL"],
    "siem_query": {
        "platform": "splunk",
        "query": 'index=main sourcetype=sysmon EventCode=1 | search exe="powershell.exe" OR exe="*\\powershell.exe" | table parent_exe, exe, command_line, hostname',
        "data_model_fields_used": ["process/create/exe", "process/create/parent_exe"],
        "caveats": "Requires Sysmon EventCode 1 (Process Create). Field names are sourcetype-dependent; adjust exe->Image, parent_exe->ParentImage for raw Sysmon logs.",
        "confidence": "high"
    }
}

SIEM_EXAMPLE_2 = {
    "analytic_id": "CAR-2013-01-002",
    "title": "Autorun Differences",
    "data_model_references": [],  # Note: this analytic has no data_model_references
    "impl_types": ["Pseudocode"],
    "siem_query": {
        "platform": "not_applicable",
        "query": "NOT APPLICABLE: Autoruns tool output; requires tool-based detection, not log queries",
        "data_model_fields_used": [],
        "caveats": "This analytic relies on Sysinternals autoruns tool output, not streaming event logs. Cannot be expressed as Splunk SPL or KQL. Detection would require ingesting autoruns periodic output or monitoring registry directly.",
        "confidence": "high"
    }
}

SIEM_EXAMPLE_3 = {
    "analytic_id": "CAR-2013-02-008",
    "title": "Simultaneous Logins on a Host",
    "data_model_references": ["process/create/hostname"],
    "impl_types": ["Pseudocode"],
    "siem_query": {
        "platform": "kql",
        "query": 'SecurityEvent | where EventID == 4624 | summarize count() by ComputerName, Account | where count_ > 3 | join kind=inner (SecurityEvent | where EventID == 4624 | summarize min(TimeGenerated) as FirstLogin, max(TimeGenerated) as LastLogin by ComputerName, Account | where (LastLogin - FirstLogin) < 5m) on ComputerName, Account',
        "data_model_fields_used": ["process/create/hostname"],
        "caveats": "Uses Windows EventID 4624 (successful logon). Threshold (3 logins in 5 min) should be tuned per environment. Field names: ComputerName=hostname, Account=user. May generate false positives from batch jobs or load balancers.",
        "confidence": "medium"
    }
}

SIEM_EXAMPLE_4 = {
    "analytic_id": "CAR-2013-03-001",
    "title": "Reg.exe called from Command Shell",
    "data_model_references": ["process/create/exe", "process/create/parent_exe"],
    "impl_types": ["Splunk"],
    "siem_query": {
        "platform": "splunk",
        "query": 'index=main sourcetype=sysmon EventCode=1 | search exe=*reg.exe (parent_exe=cmd.exe OR parent_exe=powershell.exe OR parent_exe=cscript.exe) | table TimeCreated, ComputerName, User, parent_exe, exe, CommandLine | where CommandLine!=*query* AND CommandLine!=*export*',
        "data_model_fields_used": ["process/create/exe", "process/create/parent_exe"],
        "caveats": "Field names adjusted for Sysmon: use Image for exe, ParentImage for parent_exe in raw Sysmon logs. Filters out legitimate query/export commands. Requires Sysmon Event ID 1 (Process Create).",
        "confidence": "high"
    }
}

SIEM_EXAMPLES = [SIEM_EXAMPLE_1, SIEM_EXAMPLE_2, SIEM_EXAMPLE_3, SIEM_EXAMPLE_4]

# Few-shot examples for false positive analysis (grounded in detection logic)

FP_EXAMPLE_1 = {
    "analytic_id": "CAR-2014-04-003",
    "title": "Powershell Execution",
    "detection_logic": "process/create/exe == powershell.exe OR process/create/exe == *\\powershell.exe",
    "false_positives": {
        "scenarios": [
            "Windows Update runs PowerShell scripts via wuauserv.exe parent for patching operations (monthly)",
            "Configuration management tools (Ansible, Puppet, Chef) execute PowerShell for infrastructure automation as domain admins",
            "System Management tasks: svchost.exe spawning powershell.exe for scheduled WMI queries or task scheduler jobs"
        ],
        "risk_level": "high",
        "triage_filters": [
            "parent_exe NOT IN (svchost.exe, msiexec.exe, System, wuauserv.exe, csscript.exe)",
            "command_line NOT LIKE '%Enc%' AND NOT LIKE '%IEX%' AND NOT LIKE '%-nop%'",
            "event_time NOT BETWEEN 02:00 AND 04:00"
        ],
        "explanation": "PowerShell is a built-in Windows scripting tool heavily used by legitimate administrators and system processes. High risk of false positives because many legitimate processes spawn powershell.exe. To reduce FPs, add context: parent process names (svchost, msiexec, System), command line keywords ('-Enc', 'IEX'), or network connections.",
        "confidence": "high"
    }
}

FP_EXAMPLE_2 = {
    "analytic_id": "CAR-2013-03-001",
    "title": "Reg.exe called from Command Shell",
    "detection_logic": "process/create/exe == reg.exe AND (process/create/parent_exe == cmd.exe OR parent_exe == powershell.exe)",
    "false_positives": {
        "scenarios": [
            "System administrators manually query registry via cmd.exe for troubleshooting: 'reg query HKLM\\\\SOFTWARE\\\\...' during incident response",
            "Batch scripts deployed by IT teams (legacy config management) call reg.exe from cmd.exe to set environment variables during system provisioning",
            "Windows startup scripts (Group Policy logon scripts) execute reg.exe from cmd.exe to configure HKLM registry for domain policies"
        ],
        "risk_level": "medium",
        "triage_filters": [
            "command_line NOT LIKE '%delete%' AND NOT LIKE '%export%'",
            "registry_hive NOT LIKE '%HKCU%'",
            "parent_exe IN (cmd.exe, userinit.exe, wininit.exe)"
        ],
        "explanation": "Reg.exe is used by admins and system scripts to read/write registry. False positives occur specifically from cmd.exe parent (not PowerShell.exe parent, which is rarer). Filter by command line: 'reg query' or 'reg add' with legitimate keys (HKLM\\\\System, HKLM\\\\Software) reduce false positives. Suspicious commands: 'reg query HKCU' or 'reg delete' are more indicative.",
        "confidence": "high"
    }
}

FP_EXAMPLE_3 = {
    "analytic_id": "CAR-2013-02-008",
    "title": "Simultaneous Logins on a Host",
    "detection_logic": "count(process/create/hostname by user, hostname) > 3 within 5 min window",
    "false_positives": {
        "scenarios": [
            "Load balancer health checks: single service account (e.g., 'healthcheck') authenticated 4+ times in <5 min from different IPs for redundancy checks",
            "Batch job user: nightly ETL processes restart connections as batch_svc account from multiple job schedulers (Autosys, Control-M) within execution window",
            "Kerberos domain controller logons: user with many cached tickets logs into shared host from multiple active sessions (terminal server, RDP clients)"
        ],
        "risk_level": "medium",
        "triage_filters": [
            "user NOT IN (SYSTEM, batch_svc, healthcheck, _svc)",
            "source_ip IN (internal_subnets_only) OR source_ip NOT IN (vpn_gateway_pool)",
            "login_count EXCLUDE_IF (event_time BETWEEN 02:00 AND 04:00)"
        ],
        "explanation": "The '3 logins in 5 min' heuristic catches load balancers and batch jobs. True compromise shows rapid logons from unusual source IPs or privilege escalation attempts. Reduce FPs by: filtering on source IP (legitimate sources only), excluding known service accounts, or requiring suspicious command execution post-login.",
        "confidence": "medium"
    }
}

FP_EXAMPLES = [FP_EXAMPLE_1, FP_EXAMPLE_2, FP_EXAMPLE_3]


# Phase 4: Schema-grounded unified prompt builder

def build_schema_grounded_prompt(analytic: dict) -> str:
    """
    Build a Phase 4 unified prompt that grounds SIEM queries and false positives in the analytic's schema.

    Takes analytic dict and returns full prompt with schema constraints and FP guidance baked in.
    """
    # Build schema-grounded SIEM section
    data_model_list = analytic.get("data_model_references", [])
    if not data_model_list or data_model_list == ["(none specified)"]:
        siem_schema_section = """
SIEM QUERY SCHEMA CONSTRAINT:
This analytic has NO data_model_references — cannot be expressed as a log query.
Respond with NOT APPLICABLE + explanation.
"""
    else:
        siem_schema_section = f"""
SIEM QUERY SCHEMA CONSTRAINT (strict - do not hallucinate fields):
Valid CAR data_model_references for this analytic:
{', '.join(data_model_list)}

These are the ONLY fields you may reference in your query.
Before outputting, verify every field in your query is in this list above.
If unsure, use NOT APPLICABLE rather than hallucinating a field name.
"""

    # Build field grounding section for false positives
    fields_for_fp = ', '.join(data_model_list) if data_model_list else '(none)'
    false_positive_guidance = f"""
FALSE POSITIVE GROUNDING:
This analytic detects based on these fields: {fields_for_fp}

When analyzing false positives:
- Ground each scenario in WHICH FIELD(S) cause the false positive
- Example: If detecting 'process/create/exe == powershell.exe', mention WHICH parent processes legitimately spawn PowerShell
- Example: If detecting 'file/create/file_path', mention WHICH programs legitimately create files in suspicious paths
- Be specific: not "windows update" but "wuauserv.exe spawns msiexec.exe -> powershell.exe during patch Tuesday"
- List 2-3 real scenarios, not hypothetical ones
"""

    analytic_context = f"""
CAR Analytic: {analytic['id']}
Title: {analytic['title']}
Description: {analytic['description']}
Platforms: {', '.join(analytic['platforms'])}
ATT&CK Techniques: {', '.join(analytic['techniques'])}
Tactics: {', '.join(analytic['tactics'])}
Data Model References: {', '.join(data_model_list) if data_model_list else '(none)'}
Implementation Types: {', '.join(analytic['impl_types'])}
"""

    full_prompt = f"""{SYSTEM_PROMPT}

{siem_schema_section}

{false_positive_guidance}

## Summary Explanation Guidance (Critical)

REQUIREMENT: Write 2-3 paragraph narrative with this structure:
1. **Paragraph 1 (WHAT)**: State the detection trigger. What specific behavior does the analytic detect?
2. **Paragraph 2 (WHY)**: Explain significance. Why does this detection matter? What is the threat?
3. **Paragraph 3 (HOW - optional)**: Describe attacker behavior. What do attackers do that triggers this?

KEY RULES:
- MINIMUM 2-3 paragraphs (not 1-2 sentences)
- Define ALL acronyms on first use (e.g., "SMB (Server Message Block)", "at.exe (AT command)")
- Include concrete examples (specific process names, file paths, tools, techniques)
- Use recognizable names: "Adobe Reader" not "AcroRd32.exe"
- Explain WHY it matters (threat significance, adversary impact)
- Explain HOW attackers use it (attack behavior pattern)
- Avoid generic language ("malicious activity" is too vague)

EXAMPLES OF GOOD STRUCTURE:
Paragraph 1: "This analytic detects when cmd.exe (the Windows Command Prompt) is spawned by an unusual or unexpected parent process. Legitimate cmd.exe instances are typically launched by explorer.exe or another cmd.exe, so seeing parents like AcroRd32.exe (Adobe Reader) or OUTLOOK.EXE launching cmd.exe is a strong indicator of malicious activity."

Paragraph 2: "This matters because it signals potential exploitation of malicious documents. When attackers embed code in PDFs or Office documents, they often use the application's process (e.g., Adobe Reader, Outlook) to spawn cmd.exe as the first stage of code execution. This parent-child relationship is highly abnormal and almost never occurs legitimately."

Paragraph 3 (optional): "Attackers exploit document readers and email clients to launch cmd.exe because these applications have legitimate reasons to be open (users commonly read PDFs and emails), making the initial compromise less suspicious. Once cmd.exe is spawned, the attacker can use it to run further payload stages or execute reconnaissance commands."

## Few-Shot Example: False Positives (grounded in detection fields)

**Example: Reg.exe from Command Shell**
Detection: process/create/exe == reg.exe, process/create/parent_exe == cmd.exe
False Positives:
- Admins manually run 'reg query HKLM\\\\SOFTWARE' from cmd.exe for troubleshooting
- Legacy batch scripts call reg.exe from cmd.exe during system provisioning
- Group Policy logon scripts execute 'reg add' from cmd.exe to set domain policies
Risk: MEDIUM (legitimate admin activity, filtered by command line keywords)

## Task: Generate all 5 outputs

For the CAR analytic provided, generate:
1. **summary_explanation**: Plain-English explanation of what this detects
2. **attack_mapping**: Explain the ATT&CK technique/tactic mappings
3. **hunting_hypothesis**: A testable threat hunting QUESTION. MUST use a "wh-" question word (what/where/when/how many), MUST end with ?, and MUST avoid circularity. Example: "If X exploits Y, what Z will appear in log W?"
4. **siem_query**: A ready-to-run SIEM query (constrained to schema above)
5. **false_positives**: Realistic false positive scenarios (grounded in detection fields)

## Output Format
Output ONLY valid JSON, with NO additional text before or after the closing brace.

{{
  "analytic_id": "{analytic['id']}",
  "summary_explanation": {{
    "summary": "...",
    "reasoning": "...",
    "confidence": "high|medium|low"
  }},
  "attack_mapping": {{
    "techniques": [
      {{
        "technique_id": "T1059",
        "technique_name": "...",
        "subtechnique_id": "T1059.001",
        "subtechnique_name": "...",
        "tactics": ["TA0002"],
        "tactic_names": ["Execution"],
        "rationale": "...",
        "confidence": "high|medium|low"
      }}
    ]
  }},
  "hunting_hypothesis": {{
    "question": "...",
    "rationale": "...",
    "testable": true,
    "confidence": "high|medium|low"
  }},
  "siem_query": {{
    "platform": "splunk|kql|eql|not_applicable",
    "query": "...",
    "data_model_fields_used": [...],
    "caveats": "...",
    "confidence": "high|medium|low"
  }},
  "false_positives": {{
    "scenarios": ["Scenario 1: [software/process] legitimately [action] in [context]", "Scenario 2: ..."],
    "risk_level": "high|medium|low",
    "explanation": "Which field(s) cause FPs; how to filter them",
    "confidence": "high|medium|low"
  }}
}}

## Analytic Details
{analytic_context}
"""
    return full_prompt

