# aws_eks_cluster

## Overview

Validates AWS EKS cluster configurations via the AWS CLI. Checks endpoint access, VPC placement, logging, OIDC identity, security groups, and authentication mode. Returns scalar fields for common security checks and the full API response as RecordData for deep inspection.

**Platform:** AWS (requires `aws` CLI binary with EKS read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The EKS API returns **camelCase** field names (e.g., `resourcesVpcConfig`, `roleArn`). Record check field paths must use camelCase accordingly.

---

## Object Fields

| Field          | Type   | Required | Description                                | Example     |
| -------------- | ------ | -------- | ------------------------------------------ | ----------- |
| `cluster_name` | string | **Yes**  | EKS cluster name (exact match)             | `scanset`   |
| `region`       | string | No       | AWS region override (passed as `--region`) | `us-east-1` |

- `cluster_name` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.
- If `region` is omitted, the AWS CLI's default region resolution applies (env vars, config file, instance metadata).

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command: describe-cluster

Retrieves cluster configuration by name.

**Collector call:** `client.execute("eks", "describe-cluster", &["--name", cluster_name])`

**Resulting command:**

```
aws eks describe-cluster --name scanset --output json
aws eks describe-cluster --name scanset --region us-east-1 --output json    # with region
```

**Response parsing:**

1. Extract `response["cluster"]` as a JSON object (not an array — single cluster response)
2. If the API returns a `ResourceNotFoundException` error (detected in the error string), set `found = false` rather than returning an error
3. Any other API error is returned as `CollectionError::CollectionFailed`

**Scalar field extraction from the cluster object:**

| Collected Field             | JSON Path                                           | Extraction   |
| --------------------------- | --------------------------------------------------- | ------------ |
| `cluster_name`              | `cluster.name`                                      | `.as_str()`  |
| `status`                    | `cluster.status`                                    | `.as_str()`  |
| `version`                   | `cluster.version`                                   | `.as_str()`  |
| `role_arn`                  | `cluster.roleArn`                                   | `.as_str()`  |
| `vpc_id`                    | `cluster.resourcesVpcConfig.vpcId`                  | `.as_str()`  |
| `endpoint_public_access`    | `cluster.resourcesVpcConfig.endpointPublicAccess`   | `.as_bool()` |
| `endpoint_private_access`   | `cluster.resourcesVpcConfig.endpointPrivateAccess`  | `.as_bool()` |
| `cluster_security_group_id` | `cluster.resourcesVpcConfig.clusterSecurityGroupId` | `.as_str()`  |
| `authentication_mode`       | `cluster.accessConfig.authenticationMode`           | `.as_str()`  |

Each field is only added if the JSON key exists and has the expected type. Missing keys result in the field being absent from collected data.

**Sample response (abbreviated):**

```json
{
  "cluster": {
    "name": "scanset",
    "arn": "arn:aws:eks:us-east-1:123456789012:cluster/scanset",
    "status": "ACTIVE",
    "version": "1.32",
    "roleArn": "arn:aws:iam::123456789012:role/example-cluster-role",
    "endpoint": "https://ABC123.gr7.us-east-1.eks.amazonaws.com",
    "resourcesVpcConfig": {
      "vpcId": "vpc-0fedcba9876543210",
      "subnetIds": ["subnet-0cccccccccccccccc", "subnet-0a1b2c3d4e5f6a7b8"],
      "securityGroupIds": ["sg-0abc123def456789"],
      "clusterSecurityGroupId": "sg-0cccccccccccccccc0",
      "endpointPublicAccess": true,
      "endpointPrivateAccess": true,
      "publicAccessCidrs": ["0.0.0.0/0"]
    },
    "kubernetesNetworkConfig": {
      "serviceIpv4Cidr": "172.20.0.0/16"
    },
    "logging": {
      "clusterLogging": [
        {
          "types": [
            "api",
            "audit",
            "authenticator",
            "controllerManager",
            "scheduler"
          ],
          "enabled": false
        }
      ]
    },
    "identity": {
      "oidc": {
        "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/ABC123DEF456"
      }
    },
    "accessConfig": {
      "authenticationMode": "API_AND_CONFIG_MAP"
    },
    "platformVersion": "eks.35",
    "tags": {
      "Project": "scanset"
    }
  }
}
```

### Error Detection

`AwsClient::execute` checks the command exit code. On non-zero exit, stderr is inspected for specific patterns:

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| `does not exist` or `not found`              | `AwsError::ResourceNotFound` |
| Anything else                                | `AwsError::CommandFailed`    |

Additionally, the collector checks the error string for `ResourceNotFoundException`. If matched, it treats this as a not-found condition (`found = false`) rather than a collection error.

---

## Collected Data Fields

### Scalar Fields

| Field                       | Type    | Always Present | Source                                               |
| --------------------------- | ------- | -------------- | ---------------------------------------------------- |
| `found`                     | boolean | Yes            | Derived — `true` if cluster was found                |
| `cluster_name`              | string  | When found     | `name` (string)                                      |
| `status`                    | string  | When found     | `status` (string)                                    |
| `version`                   | string  | When found     | `version` (string)                                   |
| `role_arn`                  | string  | When found     | `roleArn` (string)                                   |
| `vpc_id`                    | string  | When found     | `resourcesVpcConfig.vpcId` (string)                  |
| `endpoint_public_access`    | boolean | When found     | `resourcesVpcConfig.endpointPublicAccess` (boolean)  |
| `endpoint_private_access`   | boolean | When found     | `resourcesVpcConfig.endpointPrivateAccess` (boolean) |
| `cluster_security_group_id` | string  | When found     | `resourcesVpcConfig.clusterSecurityGroupId` (string) |
| `authentication_mode`       | string  | When found     | `accessConfig.authenticationMode` (string)           |

### RecordData Field

| Field      | Type       | Always Present | Description                                                            |
| ---------- | ---------- | -------------- | ---------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full cluster object from `describe-cluster`. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the complete `cluster` object as returned by the EKS API:

```rust
let record_data = RecordData::from_json_value(cluster.clone());
```

### Top-level paths

| Path                 | Type    | Example Value                                           |
| -------------------- | ------- | ------------------------------------------------------- |
| `name`               | string  | `"scanset"`                                             |
| `arn`                | string  | `"arn:aws:eks:us-east-1:123456789012:cluster/scanset"`  |
| `status`             | string  | `"ACTIVE"`                                              |
| `version`            | string  | `"1.32"`                                                |
| `roleArn`            | string  | `"arn:aws:iam::123456789012:role/example-cluster-role"` |
| `endpoint`           | string  | `"https://ABC123.gr7.us-east-1.eks.amazonaws.com"`      |
| `platformVersion`    | string  | `"eks.35"`                                              |
| `deletionProtection` | boolean | `false`                                                 |

### VPC config paths (`resourcesVpcConfig.*`)

| Path                                        | Type    | Example Value                |
| ------------------------------------------- | ------- | ---------------------------- |
| `resourcesVpcConfig.vpcId`                  | string  | `"vpc-0fedcba9876543210"`    |
| `resourcesVpcConfig.endpointPublicAccess`   | boolean | `true`                       |
| `resourcesVpcConfig.endpointPrivateAccess`  | boolean | `true`                       |
| `resourcesVpcConfig.clusterSecurityGroupId` | string  | `"sg-0cccccccccccccccc0"`     |
| `resourcesVpcConfig.subnetIds.0`            | string  | `"subnet-0cccccccccccccccc"` |
| `resourcesVpcConfig.subnetIds.*`            | string  | (all subnet IDs)             |
| `resourcesVpcConfig.publicAccessCidrs.0`    | string  | `"0.0.0.0/0"`                |
| `resourcesVpcConfig.publicAccessCidrs.*`    | string  | (all public CIDRs)           |

### Logging paths (`logging.*`)

| Path                               | Type    | Example Value        |
| ---------------------------------- | ------- | -------------------- |
| `logging.clusterLogging.0.enabled` | boolean | `false`              |
| `logging.clusterLogging.0.types.0` | string  | `"api"`              |
| `logging.clusterLogging.0.types.*` | string  | (all log type names) |

### Identity and access paths

| Path                              | Type   | Example Value                                                |
| --------------------------------- | ------ | ------------------------------------------------------------ |
| `identity.oidc.issuer`            | string | `"https://oidc.eks.us-east-1.amazonaws.com/id/ABC123DEF456"` |
| `accessConfig.authenticationMode` | string | `"API_AND_CONFIG_MAP"`                                       |

### Tags

| Path           | Type   | Example Value |
| -------------- | ------ | ------------- |
| `tags.Project` | string | `"scanset"`   |

---

## State Fields

### Scalar State Fields

| State Field                 | Type    | Allowed Operations              | Maps To Collected Field     |
| --------------------------- | ------- | ------------------------------- | --------------------------- |
| `found`                     | boolean | `=`, `!=`                       | `found`                     |
| `cluster_name`              | string  | `=`, `!=`                       | `cluster_name`              |
| `status`                    | string  | `=`, `!=`                       | `status`                    |
| `version`                   | string  | `=`, `!=`, `starts`             | `version`                   |
| `vpc_id`                    | string  | `=`, `!=`                       | `vpc_id`                    |
| `endpoint_public_access`    | boolean | `=`, `!=`                       | `endpoint_public_access`    |
| `endpoint_private_access`   | boolean | `=`, `!=`                       | `endpoint_private_access`   |
| `cluster_security_group_id` | string  | `=`, `!=`, `starts`             | `cluster_security_group_id` |
| `role_arn`                  | string  | `=`, `!=`, `contains`, `starts` | `role_arn`                  |
| `authentication_mode`       | string  | `=`, `!=`                       | `authentication_mode`       |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                          |
| ----------- | ----------------------- | ------------------------------------ |
| `record`    | `resource`              | Deep inspection of full API response |

Record check field paths use **camelCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                       |
| ---------------------------- | --------------------------- |
| Collector ID                 | `aws_eks_cluster_collector` |
| Collector Type               | `aws_eks_cluster`           |
| Collection Mode              | Content                     |
| Required Capabilities        | `aws_cli`, `eks_read`       |
| Expected Collection Time     | ~2000ms                     |
| Memory Usage                 | ~10MB                       |
| Network Intensive            | Yes                         |
| CPU Intensive                | No                          |
| Requires Elevated Privileges | No                          |
| Batch Collection             | No                          |

### Authentication

The `AwsClient` uses `Command::new("aws")` which relies on the AWS CLI's default credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Shared credentials file (`~/.aws/credentials`)
3. IAM role (EC2, ECS, Lambda)
4. IRSA (EKS)

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["eks:DescribeCluster"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                             |
| ----------- | ------------------------------------------------- |
| method_type | `ApiCall`                                         |
| description | `"Query EKS cluster configuration via AWS CLI"`   |
| target      | `"eks:<cluster_name>"`                            |
| command     | `"aws eks describe-cluster"`                      |
| inputs      | `cluster_name` (always), `region` (when provided) |

---

## ESP Examples

### Validate cluster is active in correct VPC

```esp
OBJECT scanset_cluster
    cluster_name `scanset`
    region `us-east-1`
OBJECT_END

STATE cluster_valid
    found boolean = true
    status string = `ACTIVE`
    vpc_id string = `vpc-0fedcba9876543210`
    endpoint_private_access boolean = true
    cluster_security_group_id string = `sg-0cccccccccccccccc0`
STATE_END

CTN aws_eks_cluster
    TEST all all AND
    STATE_REF cluster_valid
    OBJECT_REF scanset_cluster
CTN_END
```

### Validate public access is disabled

```esp
OBJECT scanset_cluster
    cluster_name `scanset`
    region `us-east-1`
OBJECT_END

STATE no_open_public
    found boolean = true
    endpoint_public_access boolean = false
    endpoint_private_access boolean = true
STATE_END

CTN aws_eks_cluster
    TEST all all AND
    STATE_REF no_open_public
    OBJECT_REF scanset_cluster
CTN_END
```

### Record checks for logging and OIDC

```esp
OBJECT scanset_cluster
    cluster_name `scanset`
    region `us-east-1`
OBJECT_END

STATE cluster_hardened
    found boolean = true
    status string = `ACTIVE`
    record
        field logging.clusterLogging.0.enabled boolean = true
        field identity.oidc.issuer string starts `https://oidc.eks`
        field resourcesVpcConfig.subnetIds.* string = `subnet-0cccccccccccccccc` at_least_one
    record_end
STATE_END

CTN aws_eks_cluster
    TEST all all AND
    STATE_REF cluster_hardened
    OBJECT_REF scanset_cluster
CTN_END
```

### Validate authentication mode and role

```esp
OBJECT scanset_cluster
    cluster_name `scanset`
    region `us-east-1`
OBJECT_END

STATE auth_config
    found boolean = true
    authentication_mode string = `API_AND_CONFIG_MAP`
    role_arn string contains `example-cluster-role`
STATE_END

CTN aws_eks_cluster
    TEST all all AND
    STATE_REF auth_config
    OBJECT_REF scanset_cluster
CTN_END
```

---

## Error Conditions

| Condition                                       | Error Type                   | Outcome       | Notes                                                 |
| ----------------------------------------------- | ---------------------------- | ------------- | ----------------------------------------------------- |
| Cluster not found (`ResourceNotFoundException`) | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent    |
| `cluster_name` missing from object              | `InvalidObjectConfiguration` | Error         | Required field — collector returns immediately        |
| `aws` CLI binary not found                      | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                  |
| Invalid AWS credentials                         | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error       |
| IAM access denied                               | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess` |
| JSON parse failure                              | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                |
| Incompatible CTN type                           | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_eks_cluster"`   |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"EKS cluster not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type             | Relationship                         |
| -------------------- | ------------------------------------ |
| `aws_vpc`            | Cluster runs in boundary VPC         |
| `aws_security_group` | Cluster SG controls node/pod traffic |
| `aws_subnet`         | Cluster subnets                      |
| `aws_iam_role`       | Cluster role and IRSA roles          |
| `aws_ecr_repository` | Image source for cluster workloads   |
| `k8s_resource`       | Workloads running on the cluster     |
