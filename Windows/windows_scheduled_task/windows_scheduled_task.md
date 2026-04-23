# windows_scheduled_task

## Overview

Validates a single scheduled task via `Get-ScheduledTask` combined with
`Get-ScheduledTaskInfo`. Exposes state, author, description, and
day-granularity deltas for last-run and next-run timestamps plus the
last run's HRESULT.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG checks that required maintenance tasks are Ready and run recently, that disabled-by-default tasks stay Disabled, and that last-run results are successful.

---

## Object Fields (Input)

| Field  | Type   | Required | Description                                                            | Example                                                 |
| ------ | ------ | -------- | ---------------------------------------------------------------------- | ------------------------------------------------------- |
| `path` | string | Yes      | Full task path beginning with `\`. Last segment is the task name.      | `\Microsoft\Windows\Defrag\ScheduledDefrag`, `\Microsoft\Windows\Defender\Windows Defender Scheduled Scan` |

Passed to `Get-ScheduledTask` after splitting on the final backslash. Allowed chars: alphanumerics, path separators, space, dot, hyphen, underscore, parens, brackets, braces.

---

## Collected Data Fields (Output)

| Field                 | Type    | Required | Description                                                       |
| --------------------- | ------- | -------- | ----------------------------------------------------------------- |
| `exists`              | boolean | Yes      | Task resolves                                                     |
| `state`               | string  | No       | `Unknown`, `Disabled`, `Queued`, `Ready`, or `Running`            |
| `author`              | string  | No       | Principal that authored the task definition                       |
| `description`         | string  | No       | Free-form description from task XML                               |
| `last_run_time_days`  | int     | No       | Days since LastRunTime (absent if never ran)                      |
| `next_run_time_days`  | int     | No       | Days until NextRunTime (negative=future, positive=stale/past)     |
| `last_task_result`    | int     | No       | Win32 HRESULT (0 = success) from most recent run                  |

---

## State Fields (Validation)

| Field                | Type    | Operations                                                                             | Description               |
| -------------------- | ------- | -------------------------------------------------------------------------------------- | ------------------------- |
| `exists`             | boolean | `=`, `!=`                                                                              | Task resolves             |
| `state`              | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` | Task state                |
| `author`             | string  | same as state                                                                          | Task author               |
| `description`        | string  | same as state                                                                          | Task description          |
| `last_run_time_days` | int     | `=`, `!=`, `<`, `>`, `<=`, `>=`                                                        | Days since last run       |
| `next_run_time_days` | int     | `=`, `!=`, `<`, `>`, `<=`, `>=`                                                        | Days until next run       |
| `last_task_result`   | int     | `=`, `!=`, `<`, `>`, `<=`, `>=`                                                        | Last run HRESULT          |

### Valid `state` values

`Unknown`, `Disabled`, `Queued`, `Ready`, `Running`

---

## Collection Strategy

| Property                     | Value                      |
| ---------------------------- | -------------------------- |
| Collector Type               | `windows_scheduled_task`   |
| Collection Mode              | Metadata                   |
| Required Capabilities        | `powershell_exec`          |
| Expected Collection Time     | ~1500ms                    |
| Memory Usage                 | ~1MB                       |
| Requires Elevated Privileges | No                         |

### Behaviors

None.

---

## Command Execution

Single PowerShell call chaining two cmdlets:

```
$t = Get-ScheduledTask -TaskPath '<parent>\' -TaskName '<leaf>'; $i = $t | Get-ScheduledTaskInfo; [PSCustomObject]@{ State=$t.State; Author=$t.Author; Description=$t.Description; LastRunTime=$i.LastRunTime; NextRunTime=$i.NextRunTime; LastTaskResult=$i.LastTaskResult } | ConvertTo-Json
```

`LastRunTime` and `NextRunTime` are converted Rust-side to whole-day deltas against the moment of collection. Missing values yield absent fields.

### Whitelisted Commands

| Command          | Path                                                          |
| ---------------- | ------------------------------------------------------------- |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`   |

---

## ESP Examples

### ScheduledDefrag is Ready and ran within the last 30 days

```esp
OBJECT defrag_task
    path `\Microsoft\Windows\Defrag\ScheduledDefrag`
OBJECT_END

STATE defrag_healthy
    exists boolean = true
    state string = `Ready`
    last_run_time_days int < 30
    last_task_result int = 0
STATE_END

CTN windows_scheduled_task
    TEST at_least_one all AND
    STATE_REF defrag_healthy
    OBJECT_REF defrag_task
CTN_END
```

### Custom patch task exists and is authored by patchadmin

```esp
OBJECT patch_task
    path `\Contoso\Patching\NightlyPatchCheck`
OBJECT_END

STATE authored_by_admin
    exists boolean = true
    state string = `Ready`
    author string contains `patchadmin`
STATE_END

CTN windows_scheduled_task
    TEST at_least_one all AND
    STATE_REF authored_by_admin
    OBJECT_REF patch_task
CTN_END
```

### Legacy XblGameSave task is disabled

```esp
OBJECT xbl_task
    path `\Microsoft\XblGameSave\XblGameSaveTask`
OBJECT_END

STATE disabled
    exists boolean = true
    state string = `Disabled`
STATE_END

CTN windows_scheduled_task
    TEST at_least_one all AND
    STATE_REF disabled
    OBJECT_REF xbl_task
CTN_END
```

---

## Error Conditions

| Condition                     | Symptom                                      | Effect on TEST       |
| ----------------------------- | -------------------------------------------- | -------------------- |
| Task not found                | Cmdlet error, collector emits `{}`           | `exists` = false     |
| Path missing leading `\`      | Caller-side validator rejects                | `ValidationError`    |
| Access denied (SYSTEM task)   | `Get-ScheduledTaskInfo` fails                | `CollectionFailed`   |
| Task never ran                | `LastRunTime` null                           | `last_run_time_days` absent |

---

## Platform Notes

### Windows Server 2022

- `ScheduledTasks` module auto-loads.
- Some SYSTEM-owned tasks (e.g. under `\Microsoft\Windows\UpdateOrchestrator`) require elevation to read `LastTaskResult`.
- Day-granularity deltas avoid timezone drift; compare with `<` / `>` rather than equality.

### Caveats

- Task path must begin with `\`; the last segment is the task name and everything before is `TaskPath`.
- `next_run_time_days` is negative when the next run is in the future, positive when the trigger is overdue/stale.

---

## Security Considerations

- Read-only query; elevation required only for restricted SYSTEM tasks.
- Task XML may reference credential stores; description and author fields are evidentiary.
- Path validator rejects PS injection characters before invocation.

---

## Related CTN Types

| CTN Type                   | Relationship                                               |
| -------------------------- | ---------------------------------------------------------- |
| `windows_service`          | `Schedule` service must be running for tasks to trigger    |
| `windows_audit_policy`     | Audit of scheduled-task creation/modification events       |
| `windows_file_acl`         | ACLs on the task XML on disk                               |
| `windows_registry_acl`     | ACLs on `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` |
| `registry`                 | TaskCache backing keys                                     |
| `windows_security_policy`  | "Log on as a batch job" right for task principals          |
