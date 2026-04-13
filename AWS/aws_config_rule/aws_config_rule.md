# aws_config_rule

## Overview

Validates AWS Config rule configuration and compliance state via two AWS CLI calls: `describe-config-rules` for rule configuration and `describe-compliance-by-config-rule` for compliance result. Both responses are merged into RecordData.

**Platform:** AWS (requires `aws` CLI binary with Config read permissions)
**Collection Method:** Two sequential AWS CLI commands per object via `AwsClient`

---

## Object Fields

| Field       | Type   | Required | Description                                | Example                         |
| ----------- | ------ | -------- | ------------------------------------------ | ------------------------------- |
| `rule_name` | string | **Yes**  | Config rule name (exact match)             | `example-org-ebs-encrypted` |
| `region`    | string | No       | AWS region override (passed as `--region`) | `us-east-1`                     |

---

## Commands Executed

### Command 1: describe-config-rules

```
aws configservice describe-config-rules --config-rule-names example-org-ebs-encrypted --output json
```

**Sample response:**

```json
{
  "ConfigRules": [
    {
      "ConfigRuleName": "example-org-ebs-encrypted",
      "ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-yg7y5h",
      "ConfigRuleId": "config-rule-yg7y5h",
      "Description": "EBS volumes must be encrypted - KSI-SVC-VRI",
      "Source": {
        "Owner": "AWS",
        "SourceIdentifier": "ENCRYPTED_VOLUMES"
      },
      "ConfigRuleState": "ACTIVE"
    }
  ]
}
```

### Command 2: describe-compliance-by-config-rule

```
aws configservice describe-compliance-by-config-rule --config-rule-names example-org-ebs-encrypted --output json
```

**Sample response:**

```json
{
  "ComplianceByConfigRules": [
    {
      "ConfigRuleName": "example-org-ebs-encrypted",
      "Compliance": {
        "ComplianceType": "COMPLIANT"
      }
    }
  ]
}
```

**Compliance type values:** `COMPLIANT`, `NON_COMPLIANT`, `NOT_APPLICABLE`, `INSUFFICIENT_DATA`

`INSUFFICIENT_DATA` means the rule has not yet evaluated any resources — typically seen shortly after rule creation.

---

## Collected Data Fields

### Scalar Fields

| Field               | Type    | Always Present | Source                                                       |
| ------------------- | ------- | -------------- | ------------------------------------------------------------ |
| `found`             | boolean | Yes            | Derived — `true` if rule found                               |
| `rule_name`         | string  | When found     | `ConfigRuleName`                                             |
| `rule_state`        | string  | When found     | `ConfigRuleState` — `ACTIVE`, `DELETING`, `DELETING_RESULTS` |
| `source_owner`      | string  | When found     | `Source.Owner` — `AWS` or `CUSTOM_LAMBDA`                    |
| `source_identifier` | string  | When found     | `Source.SourceIdentifier` — AWS managed rule identifier      |
| `description`       | string  | When found     | `Description`                                                |
| `compliance_type`   | string  | When found     | `Compliance.ComplianceType` from second call                 |

### RecordData Field

| Field      | Type       | Always Present | Description                                                       |
| ---------- | ---------- | -------------- | ----------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged rule config + compliance result. Empty `{}` when not found |

---

## RecordData Structure

```
Rule.ConfigRuleName          → "example-org-ebs-encrypted"
Rule.ConfigRuleArn           → "arn:aws:config:us-east-1:..."
Rule.ConfigRuleState         → "ACTIVE"
Rule.Source.Owner            → "AWS"
Rule.Source.SourceIdentifier → "ENCRYPTED_VOLUMES"
Rule.Description             → "EBS volumes must be encrypted - KSI-SVC-VRI"
Compliance.Compliance.ComplianceType → "COMPLIANT"
```

---

## State Fields

| State Field         | Type       | Allowed Operations              | Maps To Collected Field |
| ------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`             | boolean    | `=`, `!=`                       | `found`                 |
| `rule_name`         | string     | `=`, `!=`                       | `rule_name`             |
| `rule_state`        | string     | `=`, `!=`                       | `rule_state`            |
| `source_owner`      | string     | `=`, `!=`                       | `source_owner`          |
| `source_identifier` | string     | `=`, `!=`                       | `source_identifier`     |
| `description`       | string     | `=`, `!=`, `contains`, `starts` | `description`           |
| `compliance_type`   | string     | `=`, `!=`                       | `compliance_type`       |
| `record`            | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                 | Value                       |
| ------------------------ | --------------------------- |
| Collector ID             | `aws_config_rule_collector` |
| Collector Type           | `aws_config_rule`           |
| Collection Mode          | Content                     |
| Required Capabilities    | `aws_cli`, `config_read`    |
| Expected Collection Time | ~2000ms (two API calls)     |
| Memory Usage             | ~2MB                        |
| Batch Collection         | No                          |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "config:DescribeConfigRules",
    "config:DescribeComplianceByConfigRule"
  ],
  "Resource": "*"
}
```

---

## ESP Examples

### Config rule active and compliant (KSI-CMT-VTD, KSI-MLA-LET)

```esp
OBJECT ebs_encrypted_rule
    rule_name `example-org-ebs-encrypted`
    region `us-east-1`
OBJECT_END

STATE rule_compliant
    found boolean = true
    rule_state string = `ACTIVE`
    compliance_type string = `COMPLIANT`
    source_owner string = `AWS`
    source_identifier string = `ENCRYPTED_VOLUMES`
STATE_END

CTN aws_config_rule
    TEST all all AND
    STATE_REF rule_compliant
    OBJECT_REF ebs_encrypted_rule
CTN_END
```

---

## Error Conditions

| Condition                                    | Error Type                   | Outcome       |
| -------------------------------------------- | ---------------------------- | ------------- |
| Rule not found (`NoSuchConfigRuleException`) | N/A (not an error)           | `found=false` |
| `rule_name` missing from object              | `InvalidObjectConfiguration` | Error         |
| IAM access denied                            | `CollectionFailed`           | Error         |
| Compliance call fails after rule found       | `CollectionFailed`           | Error         |
| Incompatible CTN type                        | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type              | Relationship                                            |
| --------------------- | ------------------------------------------------------- |
| `aws_config_recorder` | Recorder must be active for rules to evaluate           |
| `aws_ebs_volume`      | `ENCRYPTED_VOLUMES` rule validates EBS encryption       |
| `aws_s3_bucket`       | `S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED` validates S3 |
