# Google OSS VRP Report — Supply Chain: Fork CI can write shared build caches (policy bypass)

**Program:** Google Open Source Software Vulnerability Reward Program (OSS VRP)  
**Category:** Supply chain compromise — build integrity / distributed artifact integrity  
**Target repositories:**
- `protocolbuffers/protobuf` (consumer of CI)
- `protocolbuffers/protobuf-ci` (vulnerable composite actions; floating tag `v5`)

**Reporter classification:** Critical — shared remote cache write from attacker-controlled workflow code, overlapping release build cache namespaces, contradicting project’s own security model.

---

## 1. Summary

`protocolbuffers/protobuf` documents a clear security model for GitHub Actions:

> Forked PRs receive **read-only** access to Bazel remote caches and sccache; writes are disallowed.

The implementation in `protocolbuffers/protobuf-ci@v5` **does not enforce that model**:

| Control | Documented policy | Actual code |
|--------|-------------------|-------------|
| Bazel remote cache (`protobuf-bazel-cache`) | No uploads from forks | Never sets `--remote_upload_local_results=false` on `pull_request_target`; Bazel default is **`true`** |
| sccache (`protobuf-sccache`) | No writes from forks | Read-only guard **commented out**; always `SCCACHE_GCS_RW_MODE=READ_WRITE` |
| ccache (GitHub Actions cache) | Careful fork hardening elsewhere | Uses full `actions/cache` (save) on `pull_request_target` (base-branch cache scope) |

Additionally, every labeled fork PR runs the **`linux-release` / `x86_64`** job with sccache prefix `linux-release-x86_64` — the same prefix used by release-oriented CMake CI — so poisoned objects sit directly on the release compilation path.

**Approval bypass (VRP requirement):** The fork path is gated by the `:a: safe for tests` label. This report includes a **TOCTOU** attack scenario against that gate (explicitly listed as acceptable in OSS VRP rules). Without TOCTOU, the same bug is still an **insider-risk / post-stamp cache write** failure of a security boundary the project claims to enforce.

---

## 2. Affected software versions

| Component | Version / pin |
|-----------|----------------|
| `protocolbuffers/protobuf` | `main` @ `7c02abb54a316986679e909ed0c044139133a77c` (audited); any revision using `protobuf-ci@v5` + `test_runner.yml` `pull_request_target` flow |
| `protocolbuffers/protobuf-ci` | Floating tag **`v5`** → `e6f43bbf992213fb28a21fab10368dfd9dd3cb13` (`v5.0.3`) |
| Vulnerable files | `internal/bazel-setup/action.yml`, `sccache/action.yml`, `ccache/action.yml` |
| Bazel behavior | `--remote_upload_local_results` **defaultValue = "true"** (Bazel `RemoteOptions.java`, current master and recent releases) |
| Consumer workflows | `protobuf/.github/workflows/test_runner.yml`, `test_cpp.yml` (`linux-release`), language `test_*.yml` passing `secrets.GAR_SERVICE_ACCOUNT` |

Evidence copies: `evidence/` in this report package.

---

## 3. Root cause (technical)

### 3.1 Bazel remote cache — inverted / incomplete write gate

From `protobuf-ci/internal/bazel-setup/action.yml`:

```yaml
- name: Configure Bazel caching
  if: ${{ inputs.bazel-cache && !github.event.act_local_test }}
  run: >-
    echo "BAZEL_FLAGS=$BAZEL_FLAGS
    --google_credentials=${{ inputs.credentials-file }}
    --remote_cache=https://storage.googleapis.com/protobuf-bazel-cache/protobuf/gha/${{ inputs.bazel-cache }}" >> $GITHUB_ENV

- name: Configure Bazel cache writing
  # External runs should never write to our caches.
  if: ${{ github.event_name != 'pull_request_target' && inputs.bazel-cache && !github.event.act_local_test }}
  run: echo "BAZEL_FLAGS=$BAZEL_FLAGS --remote_upload_local_results" >> $GITHUB_ENV
```

Problems:

1. Comment says external runs must not write.
2. Code only **adds** `--remote_upload_local_results` for trusted events.
3. Bazel’s default is already **true**, so the trusted branch is a no-op.
4. For `pull_request_target`, the flag is left unset → **default true → uploads enabled**.
5. Correct hardening would be:
   `--remote_upload_local_results=false` (or `--noremote_upload_local_results`) on `pull_request_target`.

**How `GAR_SERVICE_ACCOUNT` reaches fork jobs:** `test_runner.yml` calls reusable test workflows with `secrets: inherit` after the safety gate. Example (C++ job; the same pattern is used for Bazel, Java, Python, Ruby, PHP, etc.):

```yaml
# protocolbuffers/protobuf .github/workflows/test_runner.yml
cpp:
  name: C++
  needs: [set-vars]
  uses: ./.github/workflows/test_cpp.yml
  with:
    continuous-run: ${{ needs.set-vars.outputs.continuous-run }}
    safe-checkout: ${{ needs.set-vars.outputs.checkout-sha }}
    continuous-prefix: ${{ needs.set-vars.outputs.continuous-prefix }}
  secrets: inherit
```

Those child workflows then pass the secret into composite actions, e.g. `credentials: ${{ secrets.GAR_SERVICE_ACCOUNT }}` in `test_cpp.yml` / `test_bazel.yml`, which materialize `--google_credentials=...` for the remote cache.

Cache pathnames are shared with post-submit, e.g. `cpp_linux/...`, `python_linux/...`, `java_linux/...` (see `test_*.yml` `bazel-cache:` values).

### 3.2 sccache — explicit READ_WRITE on forks

From `protobuf-ci/sccache/action.yml`:

```yaml
# Only trusted runs should have write access to our caches.
- name: Enable sccache cache writing
  # Always use read-write mode because of https://github.com/mozilla/sccache/issues/1886
  #if: ${{ github.event_name != 'pull_request_target' }}
  run: echo "SCCACHE_GCS_RW_MODE=READ_WRITE" >> $GITHUB_ENV
```

Bucket: `protobuf-sccache`.

### 3.3 Release-prefix overlap on every labeled fork PR

From `protobuf/.github/workflows/test_cpp.yml` job `linux-release`:

```yaml
matrix:
  arch: [x86_64, aarch64]
  include:
    - arch: aarch64
      continuous-only: true
# x86_64 has NO continuous-only → runs on normal labeled presubmits
...
cache-prefix: linux-release-${{ matrix.arch }}
```

So **`linux-release-x86_64` sccache is writable from a labeled fork PR**, then reused by privileged continuous/post-submit release builds.

### 3.4 Policy contradiction (project’s own docs)

`protobuf/.github/workflows/README.md`:

- “We do not allow forked PRs to upload updates to our Bazel caches, but they do use them.”
- sccache: “disallow writing in PRs from forks.”
- Forks after approval: “read-only access to our caches and Docker images, but will generally disallow any writes to shared resources.”

Implementation violates all three statements.

---

## 4. Attack scenario

### 4.1 Actor

External contributor with ability to open a PR from a fork (no maintainer role).

### 4.2 Approval bypass — TOCTOU on `:a: safe for tests`

OSS VRP accepts TOCTOU to bypass “PR must be approved” requirements.

**Time-of-check:** A maintainer reviews PR diff at commit `GOOD` (or reviews in the GitHub UI) and applies `:a: safe for tests`.

**Time-of-use:** `test_runner.yml` on `pull_request_target` / `labeled` records:

```yaml
echo "sha=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT
```

and later checks out that SHA with `GAR_SERVICE_ACCOUNT` inherited into reusable workflows.

**Race (TOCTOU):**

1. Attacker opens PR with benign commit `GOOD`.
2. Maintainer begins review of `GOOD`.
3. Attacker force-pushes commit `BAD` (malicious `BUILD` / test / CMake path that runs arbitrary commands in CI).
4. Maintainer clicks the safety label (check = “this PR is safe”) while HEAD is already `BAD`, or in the race window where the label webhook samples `head.sha = BAD` after a last-second force-push.
5. CI pins `BAD`, not the reviewed tree — **the human check and the automated use diverge**.

This matches the VRP language: exploitability without relying on a *correct* maintainer approval of the malicious tree; the gate is TOCTOU’d.

> Note: SHA pinning closes *post-webhook* force-push mutation, but does **not** close review-vs-label TOCTOU (TOC = human review of GOOD, TOU = label event / CI of BAD).

### 4.3 Post-bypass exploitation (build integrity)

Once `BAD` runs under `pull_request_target` with `GAR_SERVICE_ACCOUNT`:

1. **sccache poison (highest direct overlap):**  
   Write malicious compilation results to `protobuf-sccache` under prefix `linux-release-x86_64` (and other prefixes used by cmake jobs).

2. **Bazel remote cache poison:**  
   Because uploads are not disabled, Bazel (or direct GCS API using the same credentials file) can write `ActionResult` objects under  
   `gs://protobuf-bazel-cache/protobuf/gha/<shared-key>/...`.

3. **Consume on privileged CI:**  
   `push` to `main`, `schedule`, and continuous jobs use the same cache backends/prefixes with full trust and produce release artifacts (protoc binaries, language wheels/jars via internal release pipelines, Bazel tarballs, `protobuf-php` sync on tags, BCR publish).

4. **Impact amplification:**  
   Poisoned build cache → compromised `protoc` / runtime libraries → downstream Google OSS and third-party software that consume official protobuf artifacts (classic supply-chain integrity break).

Optional amplification (separate Bazel product issue already researched by reporter): remote `ActionResult` symlink-target injection in Bazel’s `createSymlinks()` turns a writable shared cache into host filesystem influence / potential RCE on cache consumers. Even without that, **arbitrary object replacement in a trusted compile cache** is sufficient for silent binary backdoors in CI outputs.

### 4.4 Credential exposure (assisting factors)

These are separate from the missing Bazel upload flag; together they make a write-gate fix incomplete unless credentials are also constrained.

**4.4.1 Secrets reach the job**  
`test_runner.yml` uses `secrets: inherit` on reusable workflows (snippet in §3.1). Child jobs therefore receive `GAR_SERVICE_ACCOUNT` on `pull_request_target` once the safety gate passes.

**4.4.2 Credentials land on disk**  
`protobuf-ci` `internal/gcloud-auth` uses `google-github-actions/auth`, which writes a service-account JSON credentials file and exports its path (`credentials-file` / `CREDENTIALS_FILE`).

**4.4.3 Credentials are visible to untrusted build steps**  
Docker-based actions mount `${{ github.workspace }}` into the container and pass credential paths (including basename-under-`/workspace` patterns in `bazel-docker`). Attacker-controlled tests/`BUILD`/CMake steps can read that JSON.

**4.4.4 Direct API use bypasses Bazel flags**  
With the SA JSON, a malicious step can call GCS/GAR APIs directly. That bypasses any `--remote_upload_local_results=false` the workflow might set. Fixing the Bazel flag alone is not enough — the fork SA must be read-only (or credentials must not be mounted into untrusted steps).

---

## 5. Impact

| Impact | Severity |
|--------|----------|
| Write access to shared Bazel remote cache from attacker-controlled CI code | Critical (build integrity) |
| Write access to shared sccache used by `linux-release-*` jobs | Critical (release binary integrity) |
| Potential compromise of distributed protoc / language runtimes / BCR archives | Critical (ecosystem supply chain) |
| Breaks documented fork isolation model | High (security boundary failure) |
| Floating `protobuf-ci@v5` spreads the bug to every consumer of the composite actions | High |

**Confidentiality:** SA token/JSON exposure to untrusted PR code (cloud resource access beyond CI).  
**Integrity:** Primary — poisoned caches → poisoned artifacts.  
**Availability:** Cache corruption / DoS of CI (secondary; out of reward focus if only DoS).

---

## 6. Proof of concept (buildable / reproducible)

### 6.1 Static / logic PoC (no Google resources touched)

```bash
cd protobuf-supply-chain-vrp/poc
chmod +x prove_*.sh
./prove_remote_upload_gate.sh
./prove_sccache_rw.sh
./prove_ccache_gha_write.sh
```

Expected: `pull_request_target` → upload policy **NOT disabled**; sccache **READ_WRITE**; ccache uses save-capable `actions/cache`.

### 6.2 GitHub Actions simulation (on reporter’s fork only)

Copy `poc/gha_simulate_upload_gate.yml` into a personal repo under `.github/workflows/`, run `workflow_dispatch` with `simulate_event=pull_request_target`.  
Job logs show unset upload flag + Bazel source citation `defaultValue = "true"`.

### 6.3 End-to-end against protobuf CI (logs-only)

**Do not** write to, overwrite, or probe-mutate production caches (`protobuf-bazel-cache`, `protobuf-sccache`, or related GCS/GAR objects). Evidence for this report is **logs-only**.

Recommended procedure:

1. Fork `protocolbuffers/protobuf`, open a PR that adds a **non-destructive** probe: print whether `BAZEL_FLAGS` contains `remote_upload_local_results=false`, and whether `SCCACHE_GCS_RW_MODE` is `READ_WRITE`. Do not upload cache payloads or call GCS write APIs.
2. Trigger via `:a: safe for tests` **or** demonstrate TOCTOU timeline with screenshots (GOOD review → force-push BAD → label → Actions run on BAD SHA).
3. From job logs / probe output, capture:
   - `BAZEL_FLAGS` missing `=false`
   - `SCCACHE_GCS_RW_MODE=READ_WRITE`
   - job name `Linux Release x86_64` ran on the fork PR
   - credentials file path present in the environment (path only — do not exfiltrate secret material)

IAM write capability can be inferred from the workflow wiring + SA usage in privileged post-submit jobs; it does not require a live write demonstration for triage.

### 6.4 Related buildable cache-consumer PoC

Reporter’s existing Bazel remote-cache symlink-target PoC (`bazel-cache-poison-poc/`) demonstrates why a **writable** shared Bazel cache is catastrophic for consumers. That Bazel bug is complementary impact evidence for this supply-chain write-gate failure.

---

## 7. Reproduction checklist for triagers

1. Open `https://github.com/protocolbuffers/protobuf-ci/blob/v5/internal/bazel-setup/action.yml`  
   Confirm write step only *enables* upload on non-`pull_request_target`; no `=false` on forks.
2. Open `https://github.com/protocolbuffers/protobuf-ci/blob/v5/sccache/action.yml`  
   Confirm `#if: ... pull_request_target` is commented; `READ_WRITE` always set.
3. Open `https://github.com/protocolbuffers/protobuf/blob/main/.github/workflows/README.md`  
   Confirm documented read-only fork policy.
4. Open `test_cpp.yml` `linux-release` matrix — confirm `x86_64` is not `continuous-only` and uses `linux-release-${arch}` sccache prefix.
5. Run `poc/prove_remote_upload_gate.sh` — confirm verdict string `UPLOADS ENABLED` for `pull_request_target`.
6. Confirm Bazel default via `RemoteOptions.java` `remote_upload_local_results` `defaultValue = "true"`.

---

## 8. Remediations (suggested)

1. **bazel-setup:** For `pull_request_target`, append  
   `--remote_upload_local_results=false`.  
   Keep trusted events explicit `true` if desired.
2. **sccache:** Restore event guard; use read-only mode for forks, or separate buckets/prefixes + IAM denying `create` for the fork SA.
3. **Separate credentials:** Fork CI SA = read-only on cache buckets and Artifact Registry pull-only; never the same SA as post-submit writers.
4. **Do not mount writable creds into untrusted builds;** prefer short-lived OIDC with audiences constrained to read paths.
5. **ccache:** Mirror `composer-setup` — `actions/cache/restore` only on `pull_request_target`.
6. **Release prefixes:** Never share `linux-release-*` sccache prefixes with fork-presubmit jobs.
7. **TOCTOU:** Require label + matching reviewed commit OID (e.g. commit status / sticky comment with SHA, or Actions environment approval bound to `head.sha` that maintainers attest).
8. Pin `protobuf-ci` to full SHAs instead of floating `v5` where possible.

---

## 9. What this is / isn’t under VRP

| Claim | Fits VRP? |
|-------|-----------|
| Supply chain: compromise build integrity leading to malicious distributed artifacts | Yes |
| GitHub Actions misconfiguration in Google OSS | Yes |
| Demonstrated without correct maintainer approval of malicious tree via TOCTOU | Yes (per program text) |
| Memory corruption in protoc parsers | Out of scope for *this* report (separate) |
| Requires honest maintainer approval of BAD and no race | Credit / insider-risk only — we argue TOCTOU elevates beyond that |

---

## 10. Timeline / artifacts

- Audit date: 2026-07-31  
- `protobuf-ci` pin: `e6f43bbf992213fb28a21fab10368dfd9dd3cb13` (`v5` / `v5.0.3`)  
- `protobuf` pin: `7c02abb54a316986679e909ed0c044139133a77c`  
- Package: `protobuf-supply-chain-vrp/` (this directory)
