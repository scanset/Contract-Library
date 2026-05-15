# computed_values

## Overview

Special-purpose CTN for **testing and development** — validates computed variables produced by RUN operations rather than collected data. Use it to assert that a RUN block produces an expected intermediate value during policy authoring or unit testing. **Not for compliance scans.**

**Platform:** Cross-platform (engine-internal, no collector I/O)
**Collection Method:** None — the contract validates against resolved variables in the execution context, not against external data

**Note:** This CTN exists to give policy authors a way to assert RUN-block output during development. Production compliance policies should use a real collector CTN (e.g. `file_metadata`, `aws_iam_role`) instead. The collection strategy reports zero work because no I/O actually happens.

---

## Object Fields

Both fields are informational only — they don't drive collection, just label the test.

| Field         | Type   | Required | Description                                | Example                  |
| ------------- | ------ | -------- | ------------------------------------------ | ------------------------ |
| `type`        | string | No       | Validation type marker (e.g. `test`)       | `test`, `validation`     |
| `description` | string | No       | What's being validated                     | `RUN operations test`    |

---

## Commands Executed

**None.** This CTN does not call any external command, API, or filesystem. The "collection" is a no-op; validation runs against the variables already resolved in the engine's execution context.

---

## Collected Data Fields

`computed_values` does not produce a conventional `CollectedData` shape. The state-field validation runs against **resolved variables in the engine context** — typically populated by a preceding `RUN` block.

A required marker field `_validation_marker` is present in the contract definition for engine validation but is not user-meaningful.

---

## State Fields

State field names are wildcard-style — any variable name resolved by RUN is fair game. Three type families are accepted, each matched by suffix convention:

| State Field Pattern | Type    | Allowed Operations                                              | Description                |
| ------------------- | ------- | --------------------------------------------------------------- | -------------------------- |
| `*` (any name)      | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`         | Any string-valued variable |
| `*_int`             | int     | `=`, `!=`, `>`, `>=`, `<`, `<=`                                 | Any integer variable       |
| `*_bool`            | boolean | `=`, `!=`                                                       | Any boolean variable       |

The state-field name MUST match the variable name produced by the RUN block.

---

## Collection Strategy

| Property                     | Value                |
| ---------------------------- | -------------------- |
| Collector ID                 | (no collector — engine-internal) |
| Collector Type               | `computed_values`    |
| Collection Mode              | Metadata (nominal — no actual collection happens) |
| Required Capabilities        | (none)               |
| Expected Collection Time     | ~0ms                 |
| Memory Usage                 | ~0MB                 |
| Network Intensive            | No                   |
| CPU Intensive                | No                   |
| Requires Elevated Privileges | No                   |
| Batch Collection             | No                   |

### Required Permissions

None. The CTN runs entirely inside the engine.

---

## ESP Examples

### Validate a RUN block computes an expected sum

```esp
RUN add_two
    a int = `2`
    b int = `3`
    result_int = `a + b`
RUN_END

OBJECT addition_check
    type `test`
    description `Verify add_two computes 2 + 3 = 5`
OBJECT_END

STATE result_correct
    result_int int = `5`
STATE_END

CTN computed_values
    TEST all all AND
    STATE_REF result_correct
    OBJECT_REF addition_check
CTN_END
```

### Validate string concatenation

```esp
RUN build_path
    base string = `/etc`
    leaf string = `passwd`
    full_path = `base + "/" + leaf`
RUN_END

OBJECT concat_check
    type `test`
OBJECT_END

STATE concatenated
    full_path string = `/etc/passwd`
STATE_END

CTN computed_values
    TEST all all AND
    STATE_REF concatenated
    OBJECT_REF concat_check
CTN_END
```

### Validate boolean reduction

```esp
RUN check_two_things
    a_bool = `true`
    b_bool = `true`
    both_true_bool = `a_bool AND b_bool`
RUN_END

OBJECT reduction_check
    type `test`
OBJECT_END

STATE both_passed
    both_true_bool boolean = true
STATE_END

CTN computed_values
    TEST all all AND
    STATE_REF both_passed
    OBJECT_REF reduction_check
CTN_END
```

---

## Error Conditions

| Condition                                    | Error Type                   | Outcome                          |
| -------------------------------------------- | ---------------------------- | -------------------------------- |
| State field references a variable RUN didn't define | `MissingVariable`     | Error                            |
| Type mismatch (e.g. `_int` field but RUN produced string) | `TypeMismatch`   | Error                            |
| Used in production compliance policy         | (not detected — policy lint) | Misuse — should be a real CTN    |
| Incompatible CTN type                        | `CtnContractValidation`      | Error                            |

---

## Related CTN Types

| CTN Type            | Relationship                                                                |
| ------------------- | --------------------------------------------------------------------------- |
| `file_metadata`     | Use this for production policies that check file attributes                |
| `file_content`      | Use this for production policies that check file content patterns          |
| `json_record`       | Use this for production policies that parse JSON files                     |
| Any compliance CTN  | `computed_values` is dev/test only — production should always use a real collector |
