# How to Provide Feedback on Phase 4+ Threat Hunting Outputs

This guide explains how to submit feedback on generated threat hunting analytics so we can continuously improve the system.

## Why Your Feedback Matters

Your insights as threat hunting practitioners are critical to improving output quality. Feedback helps us:
- Correct technique-tactic mappings
- Improve hypothesis testability
- Reduce false positives
- Identify hallucinated field names
- Calibrate confidence levels

---

## Simple Submission Format

When you find an issue, reply with the following structure:

### Header
```
Feedback on: [ANALYTIC_ID]
Issue Type: [technique_mapping | hypothesis_quality | false_positives | siem_query | other]
```

### What Was Wrong
Describe the specific problem in 1-2 sentences:
```
Example: "T1036 (Masquerading) is marked as the technique, but this analytic is really about 
registry modifications for persistence (should be T1547.001)"
```

### Why It's Wrong
Explain the reasoning:
```
Example: "The analytic specifically monitors HKLM\Software\Microsoft\Windows\Run for additions, 
which is the classic Registry Run Keys persistence mechanism, not evasion."
```

### What Should It Be
Provide the correction:
```
Example: "Technique: T1547.001 (Boot or Logon Autostart - Registry Run Keys)
Tactic: TA0003 (Persistence)"
```

---

## Examples of Quality Feedback

### ✅ GOOD Feedback: Specific & Actionable

**Analytic**: CAR-2013-02-003  
**Issue Type**: technique_mapping

**What Was Wrong**:  
The model generated T1059 but should be more specific: this analytic detects cmd.exe spawned from parent processes like Adobe Reader (AcroRd32.exe), which is characteristic of document exploit.

**Why It's Wrong**:  
T1059 is correct at the parent technique level, but CAR specifies T1059.003 (Windows Command Shell) as the subtechnique because it's specifically about cmd.exe, not PowerShell or other interpreters.

**What Should It Be**:  
Technique: T1059.003 (Command and Scripting Interpreter - Windows Command Shell)  
Tactic: TA0002 (Execution)

---

### ✅ GOOD Feedback: SIEM Query Issue

**Analytic**: CAR-2013-05-004  
**Issue Type**: siem_query

**What Was Wrong**:  
The generated Splunk query uses field name `process_parent_exe`, which doesn't exist in our Sysmon data model.

**Why It's Wrong**:  
Our Sysmon logs use CIM field naming: the parent process field is `ParentImage` (raw Sysmon) or `parent_exe` (CIM), not `process_parent_exe`.

**What Should It Be**:  
Update field reference to: `parent_exe` or `ParentImage` (depending on your SIEM's data model)

---

### ✅ GOOD Feedback: False Positives

**Analytic**: CAR-2014-04-003  
**Issue Type**: false_positives

**What Was Wrong**:  
The analytic flags all PowerShell execution, but our automated patching system (Windows Update via wuauserv.exe → msiexec.exe → powershell.exe) triggers this rule every Tuesday during patch windows, generating 200+ daily false positives.

**Why It's Wrong**:  
The false positive analysis lists wuauserv as a legitimate parent, but doesn't account for the full call chain and time-based filtering.

**What Should It Be**:  
Add triage filter: `parent_exe NOT IN (wuauserv.exe, msiexec.exe) | search NOT earliest=-d@d | search NOT latest=today` (exclude patch Tuesday during maintenance window)

---

### ❌ BAD Feedback: Too Vague

**Analytic**: CAR-2013-05-002  
**Issue**: "This query doesn't work"

- Problem: No specific error or example
- Missing: What did you test with? What went wrong?
- Solution: Be specific: "When I run this query against Splunk, I get syntax error: invalid operator after WHERE"

---

## Feedback Submission Options

### Option 1: Email (Recommended for Complex Issues)
Send feedback to: `[analyst-inbox-tbd]`

Format: Plain text or structured as above

### Option 2: System Reply (Quick Notes)
Reply directly to the output generation system with feedback format

### Option 3: Spreadsheet (Bulk Feedback)
For multiple analytics:

| Analytic ID | Issue Type | What Was Wrong | Why | What Should It Be |
|---|---|---|---|---|
| CAR-2013-02-003 | technique_mapping | Got T1059, need subtechnique | cmd.exe is T1059.003 not generic | T1059.003 |
| CAR-2013-05-004 | siem_query | Field doesn't exist | process_parent_exe invalid | parent_exe |

---

## Frequency & Response Time

- **Feedback collected**: Monthly
- **Processing**: 1 week (categorization + pattern analysis)
- **Prompt updates**: 2-week cycle
- **Regeneration test**: Following Monday

---

## What Happens to Your Feedback

1. **Categorize**: Group by issue type (technique mapping, query, etc.)
2. **Pattern analysis**: Identify if multiple analytics have same issue
3. **Update prompts**: Refine guidance based on patterns
4. **Regenerate sample**: Re-generate affected analytics with improved prompt
5. **Measure improvement**: Track metrics (accuracy, MOQS, QVR)
6. **Document changes**: Log what changed and why

---

## Questions?

- **Technical**: Contact [security-eng-team]
- **Data model questions**: Consult CAR documentation (https://car.mitre.org/data_model)
- **MITRE ATT&CK mapping**: Check canonical mappings (https://attack.mitre.org)

---

**Last Updated**: 2026-04-30  
**Version**: 1.0
