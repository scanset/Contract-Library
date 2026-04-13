# k8s_resource

## Overview

Queries Kubernetes API resources via `kubectl get -o json` and validates
resource existence, count, and field-level checks via RecordData. Supports
filtering by kind, namespace, name, name prefix, and label selector.

**Pattern:** A (System binary - kubectl)
**Executor:** Simple + RecordData support
**RECORD:** yes

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | string | Yes | Resource kind (Pod, Namespace, Service, Node, etc.) |
| `namespace` | string | No | Namespace filter. Omit for cluster-scoped resources. |
| `name` | string | No | Exact resource name |
| `name_prefix` | string | No | Name prefix filter (client-side) |
| `label_selector` | string | No | Kubernetes label selector (server-side via -l) |

**Supported Kinds:** Pod, Namespace, Service, Deployment, StatefulSet, DaemonSet,
ConfigMap, Secret, Node, PersistentVolume, ClusterRole, ClusterRoleBinding,
NetworkPolicy, Ingress, ValidatingWebhookConfiguration, MutatingWebhookConfiguration

## Authentication

kubectl uses the kubeconfig for cluster auth. Two resolution paths:

- **ESP_KUBECONFIG env var** -> KUBECONFIG via `set_env_from`. Set in the agent's
  environment before running scans.
- **Default ~/.kube/config** -> HOME env var is forwarded via `set_env_from("HOME", "HOME")`
  so kubectl can find the default kubeconfig.

For kind clusters, the context is set automatically by `kind create cluster`.

## Commands Executed

```
kubectl get <kind> [-n <namespace>] [-l <label_selector>] [<name>] -o json
```

**Sample response (Pod list):**
```json
{
  "kind": "PodList",
  "items": [
    {
      "metadata": { "name": "kube-apiserver-control-plane", "namespace": "kube-system" },
      "spec": {
        "containers": [{
          "command": [
            "kube-apiserver",
            "--authorization-mode=Node,RBAC",
            "--client-ca-file=/etc/kubernetes/pki/ca.crt",
            ...
          ]
        }]
      }
    }
  ]
}
```

**Parsing:**
- List responses: extract `items` array
- Single resource: wrap in array
- `name_prefix` filter applied client-side after retrieval
- First item's JSON stored as `record` for field-level checks

## Collected Data Fields

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `found` | boolean | Yes | Any matching resources exist |
| `count` | int | Yes | Number of matching resources |
| `record` | string (JSON) | When found=true | First item's JSON for record checks |

## State Fields

| Field | Type | Operations |
|-------|------|------------|
| `found` | boolean | =, != |
| `count` | int | =, !=, >, <, >=, <= |
| `record` | RecordData | record checks (field path validation) |

## ESP Examples

### Check API server has RBAC authorization mode

```
OBJECT apiserver_pod
    kind `Pod`
    namespace `kube-system`
    label_selector `component=kube-apiserver`
OBJECT_END

STATE has_rbac
    found boolean = true
    record
        field spec.containers.0.command string contains `--authorization-mode` at_least_one
    record_end
STATE_END

CRI AND
    CTN k8s_resource
        TEST all all AND
        STATE_REF has_rbac
        OBJECT_REF apiserver_pod
    CTN_END
CRI_END
```

### Check no pods in default namespace

```
OBJECT default_ns_pods
    kind `Pod`
    namespace `default`
OBJECT_END

STATE no_user_pods
    count int = 0
STATE_END

CRI AND
    CTN k8s_resource
        TEST all all AND
        STATE_REF no_user_pods
        OBJECT_REF default_ns_pods
    CTN_END
CRI_END
```

### Check Kubernetes dashboard is not deployed

```
OBJECT dashboard
    kind `Pod`
    namespace `kube-system`
    label_selector `k8s-app=kubernetes-dashboard`
OBJECT_END

STATE no_dashboard
    count int = 0
STATE_END
```

## Kubernetes STIG Coverage

This CTN covers approximately 50 controls across these categories:

| Category | Controls | How |
|----------|----------|-----|
| API server flags | 24 | Record check on `spec.containers.0.command` |
| Etcd flags | 8 | Record check on etcd pod command |
| Controller manager flags | 4 | Record check on CM pod command |
| Scheduler flags | 2 | Record check on scheduler pod command |
| kubectl resource queries | 9 | found/count checks on namespaces, pods, services |
| Combined checks | 5 | Multiple resource queries |

The remaining STIG controls (file_metadata on `/etc/kubernetes/` paths,
kubelet config file checks) use `file_metadata` and `file_content` CTNs
and require direct filesystem access to the control plane node.

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| kubectl not in PATH | CollectionFailed error |
| Cluster unreachable | CollectionFailed error |
| No kubeconfig | CollectionFailed error |
| Resource kind not found | exit_code != 0, found=false, count=0 |
| No matching resources | found=false, count=0 |
| Permission denied (RBAC) | exit_code != 0, found=false |

## Related CTN Types

- `file_metadata` - permissions/ownership on K8s config files (requires node access)
- `file_content` - manifest file content checks (requires node access)
- `systemd_service` - kubelet/etcd service checks on nodes
