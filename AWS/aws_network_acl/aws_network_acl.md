# aws_network_acl

## Overview

Validates AWS Network ACL configuration via the AWS CLI. Makes a single API call using `describe-network-acls` with either a direct NACL ID lookup or filter-based lookup by VPC ID and/or tags. The `Entries` array contains both ingress and egress rules mixed together — derived scalars split them by `Egress` boolean.

**Platform:** AWS (requires `aws` CLI binary with EC2 read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The `Entries` array in the API response contains both ingress (`Egress=false`) and egress (`Egress=true`) rules in the same array, ordered by `RuleNumber`. The implicit deny-all rule appears as `RuleNumber=32767` for each direction.

**Note:** When `vpc_id` is provided without `nacl_id`, `describe-network-acls` returns all NACLs in the VPC including the default one. The collector prefers the first non-default NACL when multiple results are returned.

---

## Object Fields

| Field     | Type   | Required | Description                                | Example                             |
| --------- | ------ | -------- | ------------------------------------------ | ----------------------------------- |
| `nacl_id` | string | No\*     | Network ACL ID for direct lookup           | `acl-0123456789abcdef0`             |
| `vpc_id`  | string | No\*     | VPC ID to scope the lookup                 | `vpc-0123456789abcdef0`             |
| `tags`    | string | No\*     | Tag filter in `Key=Value` format           | `Name=example-org-nacl-private` |
| `region`  | string | No       | AWS region override (passed as `--region`) | `us-east-1`                         |

\* At least one of `nacl_id`, `vpc_id`, or `tags` must be specified.

- `nacl_id` uses `--network-acl-ids` for direct lookup
- `vpc_id` uses `--filters Name=vpc-id,Values=<value>`
- `tags` is parsed on `=` and used as `--filters Name=tag:<Key>,Values=<Value>`
- When multiple NACLs match, the first non-default NACL is preferred

---

## Commands Executed

### Command 1: describe-network-acls

**Resulting commands (examples):**

```
# By NACL ID
aws ec2 describe-network-acls --network-acl-ids acl-0123456789abcdef0 --output json

# By VPC + tag
aws ec2 describe-network-acls --filters Name=vpc-id,Values=vpc-0123456789abcdef0 --filters Name=tag:Name,Values=example-org-nacl-private --output json
```

**Sample response (abbreviated):**

```json
{
  "NetworkAcls": [
    {
      "NetworkAclId": "acl-0123456789abcdef0",
      "VpcId": "vpc-0123456789abcdef0",
      "IsDefault": false,
      "Associations": [
        {
          "NetworkAclAssociationId": "aclassoc-0a5c19a4620279bfb",
          "NetworkAclId": "acl-0123456789abcdef0",
          "SubnetId": "subnet-0aaaaaaaaaaaaaaaa"
        },
        {
          "NetworkAclAssociationId": "aclassoc-09f26c8bee31961c2",
          "NetworkAclId": "acl-0123456789abcdef0",
          "SubnetId": "subnet-0bbbbbbbbbbbbbbbb"
        }
      ],
      "Entries": [
        {
          "CidrBlock": "0.0.0.0/0",
          "Egress": true,
          "PortRange": { "From": 443, "To": 443 },
          "Protocol": "6",
          "RuleAction": "allow",
          "RuleNumber": 100
        },
        {
          "CidrBlock": "0.0.0.0/0",
          "Egress": true,
          "PortRange": { "From": 80, "To": 80 },
          "Protocol": "6",
          "RuleAction": "allow",
          "RuleNumber": 110
        },
        {
          "CidrBlock": "0.0.0.0/0",
          "Egress": true,
          "PortRange": { "From": 53, "To": 53 },
          "Protocol": "17",
          "RuleAction": "allow",
          "RuleNumber": 120
        },
        {
          "CidrBlock": "0.0.0.0/0",
          "Egress": true,
          "PortRange": { "From": 1024, "To": 65535 },
          "Protocol": "6",
          "RuleAction": "allow",
          "RuleNumber": 130
        },
        {
          "CidrBlock": "0.0.0.0/0",
          "Egress": true,
          "Protocol": "-1",
          "RuleAction": "deny",
          "RuleNumber": 32767
        },
        {
          "CidrBlock": "10.0.0.0/16",
          "Egress": false,
          "PortRange": { "From": 443, "To": 443 },
          "Protocol": "6",
          "RuleAction": "allow",
          "RuleNumber": 100
        },
        {
          "CidrBlock": "10.0.0.0/16",
          "Egress": false,
          "PortRange": { "From": 1024, "To": 65535 },
          "Protocol": "6",
          "RuleAction": "allow",
          "RuleNumber": 110
        },
        {
          "CidrBlock": "0.0.0.0/0",
          "Egress": false,
          "PortRange": { "From": 1024, "To": 65535 },
          "Protocol": "6",
          "RuleAction": "allow",
          "RuleNumber": 120
        },
        {
          "CidrBlock": "0.0.0.0/0",
          "Egress": false,
          "PortRange": { "From": 443, "To": 443 },
          "Protocol": "6",
          "RuleAction": "allow",
          "RuleNumber": 130
        },
        {
          "CidrBlock": "0.0.0.0/0",
          "Egress": false,
          "Protocol": "-1",
          "RuleAction": "deny",
          "RuleNumber": 32767
        }
      ],
      "Tags": [{ "Key": "Name", "Value": "example-org-nacl-private" }]
    }
  ]
}
```

**Derived scalars from Entries array:**

| Scalar Field          | Derivation Logic                         |
| --------------------- | ---------------------------------------- |
| `entry_count`         | Total count of all entries               |
| `ingress_entry_count` | Count of entries where `Egress == false` |
| `egress_entry_count`  | Count of entries where `Egress == true`  |
| `association_count`   | Count of entries in `Associations` array |

---

## Collected Data Fields

### Scalar Fields

| Field                 | Type    | Always Present | Source                                   |
| --------------------- | ------- | -------------- | ---------------------------------------- |
| `found`               | boolean | Yes            | Derived — `true` if NACL found           |
| `nacl_id`             | string  | When found     | `NetworkAclId`                           |
| `vpc_id`              | string  | When found     | `VpcId`                                  |
| `is_default`          | boolean | When found     | `IsDefault`                              |
| `entry_count`         | integer | When found     | Derived — total entries                  |
| `ingress_entry_count` | integer | When found     | Derived — entries where `Egress=false`   |
| `egress_entry_count`  | integer | When found     | Derived — entries where `Egress=true`    |
| `association_count`   | integer | When found     | Derived — length of `Associations` array |

### RecordData Field

| Field      | Type       | Always Present | Description                                 |
| ---------- | ---------- | -------------- | ------------------------------------------- |
| `resource` | RecordData | Yes            | Full NACL object. Empty `{}` when not found |

---

## RecordData Structure

| Path                                     | Type    | Example Value                  |
| ---------------------------------------- | ------- | ------------------------------ |
| `NetworkAclId`                           | string  | `"acl-0123456789abcdef0"`      |
| `VpcId`                                  | string  | `"vpc-0123456789abcdef0"`      |
| `IsDefault`                              | boolean | `false`                        |
| `Entries.0.CidrBlock`                    | string  | `"0.0.0.0/0"`                  |
| `Entries.0.Egress`                       | boolean | `true`                         |
| `Entries.0.Protocol`                     | string  | `"6"` (TCP)                    |
| `Entries.0.RuleAction`                   | string  | `"allow"`                      |
| `Entries.0.RuleNumber`                   | integer | `100`                          |
| `Entries.0.PortRange.From`               | integer | `443`                          |
| `Entries.0.PortRange.To`                 | integer | `443`                          |
| `Associations.0.SubnetId`                | string  | `"subnet-0aaaaaaaaaaaaaaaa"`   |
| `Associations.0.NetworkAclAssociationId` | string  | `"aclassoc-0a5c19a4620279bfb"` |

**Protocol numbers:** `"6"` = TCP, `"17"` = UDP, `"-1"` = all traffic

---

## State Fields

| State Field           | Type       | Allowed Operations              | Maps To Collected Field |
| --------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`               | boolean    | `=`, `!=`                       | `found`                 |
| `nacl_id`             | string     | `=`, `!=`                       | `nacl_id`               |
| `vpc_id`              | string     | `=`, `!=`                       | `vpc_id`                |
| `is_default`          | boolean    | `=`, `!=`                       | `is_default`            |
| `entry_count`         | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `entry_count`           |
| `ingress_entry_count` | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `ingress_entry_count`   |
| `egress_entry_count`  | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `egress_entry_count`    |
| `association_count`   | int        | `=`, `!=`, `>=`, `>`            | `association_count`     |
| `record`              | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                       |
| ---------------------------- | --------------------------- |
| Collector ID                 | `aws_network_acl_collector` |
| Collector Type               | `aws_network_acl`           |
| Collection Mode              | Content                     |
| Required Capabilities        | `aws_cli`, `ec2_read`       |
| Expected Collection Time     | ~1500ms                     |
| Memory Usage                 | ~2MB                        |
| Network Intensive            | Yes                         |
| CPU Intensive                | No                          |
| Requires Elevated Privileges | No                          |
| Batch Collection             | No                          |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["ec2:DescribeNetworkAcls"],
  "Resource": "*"
}
```

---

## ESP Examples

### Private subnet NACL is non-default and associated with two subnets

```esp
OBJECT private_nacl
    tags `Name=example-org-nacl-private`
    vpc_id `vpc-0123456789abcdef0`
    region `us-east-1`
OBJECT_END

STATE nacl_compliant
    found boolean = true
    is_default boolean = false
    association_count int >= 2
    ingress_entry_count int >= 4
    egress_entry_count int >= 4
STATE_END

CTN aws_network_acl
    TEST all all AND
    STATE_REF nacl_compliant
    OBJECT_REF private_nacl
CTN_END
```

### Record checks for specific rule inspection

```esp
STATE nacl_rules_valid
    found boolean = true
    is_default boolean = false
    record
        field Entries.0.RuleNumber int = 100
        field Entries.0.Egress boolean = true
        field Entries.0.RuleAction string = `allow`
        field Entries.0.PortRange.From int = 443
        field Entries.4.RuleNumber int = 32767
        field Entries.4.Egress boolean = true
        field Entries.4.RuleAction string = `deny`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                  | Error Type                   | Outcome       |
| -------------------------- | ---------------------------- | ------------- |
| NACL not found             | N/A (not an error)           | `found=false` |
| No lookup fields specified | `InvalidObjectConfiguration` | Error         |
| IAM access denied          | `CollectionFailed`           | Error         |
| Incompatible CTN type      | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type             | Relationship                                                             |
| -------------------- | ------------------------------------------------------------------------ |
| `aws_vpc`            | NACLs belong to VPCs                                                     |
| `aws_subnet`         | NACLs are associated with subnets                                        |
| `aws_security_group` | SGs provide stateful filtering; NACLs provide stateless defense-in-depth |
| `aws_route_table`    | Route tables + NACLs + SGs together prove network boundary control       |
