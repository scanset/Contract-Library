# Contributing to the ESP Contract Library

Thank you for your interest in contributing to the **ESP Contract Library**.

This repo is a gallery of CTN (Criterion Type Node) reference
implementations for the [Endpoint State Policy (ESP)](https://github.com/scanset/Endpoint-State-Policy)
ecosystem. Each contract is a self-contained quartet — `contract.rs`,
`collector.rs`, `executor.rs`, optional `command.rs`, plus a `.md`
spec — designed to be dropped into a downstream agent's `contract_kit/`
tree. There is no shared build; contributions are evaluated on shape,
correctness, and adherence to the patterns established by the existing
contracts.

---

## Project Philosophy

- **Educational copy-paste, not a Cargo dependency** — each contract folder
  is read in full by a human or LLM reviewing what the CTN does. Brevity
  and clarity beat cleverness.
- **One folder per CTN type** — the folder name matches the CTN type
  identifier used in `.esp` policies (e.g., `linux_tcp_listener/`).
- **Spec docs are the contract with consumers** — the `.md` file in each
  folder is the source of truth for object fields, state fields, command
  output formats, and ESP usage examples.
- **No internal references** — contracts must be free of references to
  proprietary infrastructure (paths, repo names, scanner architecture).
  Generic placeholder data only.

---

## Ways to Contribute

### 1. Bug Reports

If a contract is incorrect (wrong field name, wrong command flag, missing
allowed operation, broken example):

- Open a GitHub Issue
- Include: contract path (e.g., `RHEL9/sysctl_parameter/`), what's wrong,
  what the corrected behavior should be, and ideally a citation to the
  upstream tool documentation or the ESP engine source.

### 2. New CTN Implementations

The most common contribution: adding a new CTN type to one of the
existing platform folders. Two paths depending on scope:

- **Variant of an existing CTN** — e.g., a new field on `file_metadata`,
  a new allowed operation on `sysctl_parameter`. Open a PR against the
  existing folder.
- **New CTN type entirely** — e.g., adding a `dpkg_package` CTN to RHEL9
  (oh wait, that's a Debian thing — see "New platform" below). New CTN
  types need a new folder containing all four `.rs` files plus the `.md`
  spec.

Authoring guide: [`ESP-Agent-SDK/guides/Contract_Development_Guide.md`](https://github.com/scanset/ESP-Agent-SDK/blob/main/guides/Contract_Development_Guide.md).

### 3. New Platform Categories

Adding a whole platform (e.g., Debian, FreeBSD, GCP) requires:

- A platform folder at the repo root (e.g., `Debian/`)
- At least one working CTN inside it
- A README section update categorizing the new platform and listing its
  required contracts

Open an issue **before** building it so the platform scope can be
discussed.

### 4. Spec Doc Improvements

The `.md` files are public-facing — clearer examples, better ESP usage
samples, more accurate command-output documentation are all welcome.

### 5. README + Top-Level Hygiene

The contracts inventory in [`README.md`](README.md) lists every platform
and the CTNs in it. When you add or remove a contract, update the
relevant table in the same PR.

---

## Repository Structure

```
Contract-Library/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── Apache/                  # Apache HTTP Server CTNs
├── AWS/                     # AWS resource CTNs (44+)
├── Azure/                   # Azure resource CTNs (35+)
├── Kubernetes/              # Kubernetes API CTNs
├── M365/                    # Microsoft 365 / Entra / Purview / Intune CTNs (27)
├── Network/                 # tls_probe, http_probe
├── PostgreSQL/              # pg_config_param, pg_catalog_query, openssl_cert
├── RHEL9/                   # RHEL 9 / Rocky 9 host CTNs (16)
└── Windows/                 # Windows host CTNs (15)
```

Each `<Platform>/<ctn_type>/` folder contains:

```
<ctn_type>/
├── <ctn_type>_contract.rs    # CtnContract definition (object/state fields)
├── <ctn_type>_collector.rs   # Data collection (shells out to CLI / API)
├── <ctn_type>_executor.rs    # STATE validation logic
├── <ctn_type>_command.rs     # (optional) Command executor factory
└── <ctn_type>.md             # Spec doc with ESP usage examples
```

---

## What "Good" Looks Like

Before opening a PR, verify your contribution against this checklist:

### Contract file (`<ctn_type>_contract.rs`)

- [ ] `CtnContract::new("<ctn_type>".to_string())` — matches folder name
- [ ] Every `ObjectFieldSpec` has `description` + `example_values` + sensible `validation_notes`
- [ ] Every `StateFieldSpec` declares its `allowed_operations` (don't leave permissive defaults)
- [ ] `collection_strategy.collector_type` matches the collector's `supported_ctn_types()`
- [ ] `PerformanceHints` are honest: `expected_collection_time_ms`, `requires_elevated_privileges`

### Collector file (`<ctn_type>_collector.rs`)

- [ ] No `Command::new` — use `SystemCommandExecutor` with an explicit binary allow-list
- [ ] No `unwrap()` / `expect()` / `panic!` — use `?` propagation and `CollectionError` variants
- [ ] `CollectionMethod` is set on `CollectedData` (traceability for assessors)
- [ ] Graceful degradation for missing / inaccessible resources — return structured state, not `CollectionError`, when the absence is itself a finding

### Executor file (`<ctn_type>_executor.rs`)

- [ ] Three-phase validation: existence → state → item
- [ ] Uses the standard string-comparison module (no hand-rolled string ops)
- [ ] Failure messages include enough context for an auditor to reproduce — expected vs. actual, plus the path / resource ID

### Spec doc (`<ctn_type>.md`)

- [ ] Overview paragraph explains *what* and *why*
- [ ] Object fields table: name, type, required, description, example
- [ ] Collected data fields table: name, type, what it means
- [ ] State fields table: name, type, allowed operators, what they validate
- [ ] At least three worked ESP examples (one per common usage pattern)
- [ ] Error conditions table
- [ ] Platform / OS notes if behavior varies

### Generic placeholders only

- [ ] No real subscription IDs, tenant IDs, account numbers, or principal IDs in example values
- [ ] No `prooflayer-*` / `scanset-*` resource names (the gallery is upstream of any specific deployment)
- [ ] Use `example-org-*`, `your-vnet-name`, `00000000-0000-0000-0000-000000000000`-style placeholders

---

## Pull Request Guidelines

When opening a PR:

- **Describe the problem or capability** — what does this add or fix?
- **Cite the upstream source** — link to the AWS API doc, Azure CLI doc,
  STIG ID, etc. that backs the contract's logic
- **Update the README inventory** — the contract count and the
  per-platform list should reflect your change
- **Keep changes focused** — one CTN per PR

---

## Engine Compatibility

Contracts in this snapshot target the ESP engine version listed in
[README.md](README.md). When the engine cuts a new tag with API changes
(struct field changes, renamed CTN types, etc.), the gallery is refreshed
in lockstep — usually under a single coordinated PR that bumps every
affected contract. Don't worry about cross-version compatibility in your
contract files; the engine version is a single point in time.

---

## Signed Commits

The Contract Library is consumed in federal-compliance contexts and
requires a verifiable authorship chain. **All commits on `main` must be
signed.** The `Require signed commits` branch-protection rule is
enforced on `main`; unsigned commits will be rejected at PR merge.

### One-time setup (SSH, simpler)

If you already have an SSH key on GitHub, signing with it is the easiest
path:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Then add the same SSH key under **"Signing key"** in your GitHub
settings — this is a separate entry from the "Authentication key" slot,
even if it's the same key material:
<https://github.com/settings/keys> → "New SSH key" → set Key type to
**"Signing Key"**.

### One-time setup (GPG)

If you prefer GPG:

1. Generate a signing key if you don't have one:

   ```bash
   gpg --full-generate-key   # RSA 4096 or Ed25519 recommended
   ```

2. Export the public key and add it to your GitHub account:

   ```bash
   gpg --armor --export YOUR_KEY_ID
   # paste into https://github.com/settings/keys → "New GPG key"
   ```

3. Configure git to sign by default:

   ```bash
   git config --global user.signingkey YOUR_KEY_ID
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true
   ```

### Verifying it worked

After a commit:

```bash
git log --show-signature -1
```

The commit should show `Good signature from "Your Name <email>"`. On
GitHub, the commit listing displays a green **Verified** badge.

### Release tags

Maintainers cutting a release tag (`vX.Y.Z`) — paired with the
matching ESP engine tag — must sign the tag. Tag signing is enabled by
`tag.gpgsign = true` above.

```bash
git tag -s vX.Y.Z -m "Release vX.Y.Z (paired with engine vX.Y.Z)"
git push origin vX.Y.Z
```

---

## Security Considerations

The Contract Library is reference code that downstream agents vendor
into their own builds. A malicious or buggy contract could:

- Issue shell commands the agent didn't intend (always use
  `SystemCommandExecutor` with an allow-list)
- Leak sensitive data into the AssessorPackage envelope (collect only
  what the contract validates against)
- Cause non-deterministic results (return consistent typed values; don't
  embed timestamps or session-specific IDs in collected fields)

If you spot a security issue in an existing contract, **do not file a
public issue**. Email: **curtis@scanset.io**.

---

## Community & Conduct

The Contract Library follows a simple rule:

> Be professional, constructive, and respectful.

Strong technical opinions are welcome. Personal attacks are not.
