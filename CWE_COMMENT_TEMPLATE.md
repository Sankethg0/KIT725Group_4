# CWE Code Comment Template

Use one completed comment block for each CWE addressed in the individual component. Replace every item in square brackets with evidence from your own analysis. Keep the wording concise enough to sit beside the relevant code.

## Overall function-level patching instructions

Analyse and patch at function level. If a function contains one or more weaknesses, document the original function and provide a replacement with the same function name and the same parameter signature. Keep the vulnerable version and the replacement clearly separated, with only one version active when the program is run.

If one function contains multiple weaknesses, the replacement function must address all of them. Do not patch only the CWE assigned to you while leaving another weakness in that same function. List every identified weakness in the function's comment and explain how the replacement removes each one. If different students are assigned weaknesses in the same function, coordinate ownership and submit one complete replacement for that function.

The before-and-after tests must call the same function interface. Demonstrate that the normal feature still works and that each weakness previously demonstrated from that function is no longer exploitable after the replacement is enabled.

The worked password-masking example is separate from the assessed CWE listing. Do not use it as one of the required CWE entries.

## Vulnerable code comment

```python
# CWE IDENTIFICATION
# CWE ID and title: [CWE-XXX — official title from the permitted listing]
# Student name: [full name]
# Student ID: [student number]
# Identified by: [student name and student ID]
# Date and time: [DD Month YYYY, HH:MM, local time]
#
# PRE-PATCH ANALYSIS
# Location: [function name and line or code section]
# Function signature: [function_name(parameter_one, parameter_two, ...)]
# Other weaknesses in this function: [list every additional CWE identified here, or “none”]
# Trigger: [input, role or condition needed to reach this code]
# Root cause: [what the code does incorrectly]
# Security impact: [what an unauthorised or incorrect action can achieve]
# Evidence: [benign test input and observed result]
# Affected functionality: [normal feature affected]
#
# PATCH PLAN
# Intended change: [one sentence describing the control or design change]
# Preserved behaviour: [normal behaviour that must continue to work]
```

## Patched code comment

```python
# POST-PATCH ANALYSIS
# CWE addressed: [CWE-XXX — official title]
# Patched by: [student name and student ID]
# Replacement signature: [same function_name and parameter signature as the original]
# Other weaknesses patched in this replacement: [list every CWE fixed here, or “none”]
# Date and time: [DD Month YYYY, HH:MM, local time]
# Change made: [what was changed and where]
# Why it works: [how the change removes or reduces the root cause]
# Verification: [test performed and result after the patch]
# Functionality preserved: [normal test that still passes]
# Limitation: [remaining risk, boundary or assumption]
# Evidence: [before/after result, test name or output]
```

## Before and after flowchart notes

Use these labels when preparing the flowchart required by the specification:

```text
Input or actor
    -> relevant function
    -> vulnerable decision or operation
    -> security consequence

Input or actor
    -> relevant function
    -> patched validation or authorisation control
    -> permitted result or safe error
```

## Short example of completed wording

```python
# CWE IDENTIFICATION
# CWE ID and title: [CWE-XXX — official title]
# Date and time: [date and time]
#
# PRE-PATCH ANALYSIS
# Location: [function and line]
# Trigger: [benign trigger]
# Root cause: User-controlled data reaches [operation] without [required control].
# Security impact: An unauthorised user may [specific impact].
# Evidence: Test [name] produced [observed result].
# Affected functionality: [normal feature].
#
# POST-PATCH ANALYSIS
# Change made: [control added or unsafe operation replaced].
# Why it works: [explain the data or authorisation flow after the change].
# Verification: [test name] now produces [safe result].
# Functionality preserved: [normal test] still passes.
# Limitation: [remaining boundary or assumption].
```

## Submission checks

Before submitting, confirm that each entry:

- uses the official CWE ID and title from the permitted listing;
- includes a date and time for the work performed;
- explains the pre-patch root cause, trigger, impact and evidence;
- explains the post-patch change, verification and limitation;
- includes a before and after flowchart in the report;
- demonstrates the patch in the video and preserves normal functionality; and
- records any generative AI use and prompts as required by the assignment.

Do not claim that a CWE is addressed solely because a test passes. Link the test result to the code change and explain the security property that the patch restores.
