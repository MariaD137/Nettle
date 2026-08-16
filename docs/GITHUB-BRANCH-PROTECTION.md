# GitHub Branch Protection Setup

These settings must be configured manually in the GitHub UI since they require admin permissions.

## Configuring Branch Protection for `main`

1. Go to **Settings** > **Branches** in the repository
2. Click **Add branch protection rule** (or edit the existing rule for `main`)
3. Set **Branch name pattern**: `main`
4. Enable these settings:

### Required settings

- [x] **Require a pull request before merging**
  - [x] Require approvals: 1 (adjust based on team size)
  - [x] Dismiss stale pull request approvals when new commits are pushed
- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging
  - Add required status checks:
    - `test` (from Backend CI workflow)
    - `build` (from Frontend CI workflow)
- [x] **Require conversation resolution before merging**
- [x] **Do not allow bypassing the above settings**

### Recommended settings

- [x] **Restrict who can push to matching branches** — only allow merges via PR
- [x] **Block force pushes**
- [x] **Do not allow deletions**

## Configuring Branch Protection for `develop`

1. Add another branch protection rule for `develop`
2. Enable:
  - [x] **Require a pull request before merging**
  - [x] **Require status checks to pass before merging**
    - Same checks as `main`
  - [x] **Block force pushes**
  - [x] **Do not allow deletions**

Approval requirements can be relaxed on `develop` to allow faster iteration.

## Verifying Protection

After configuring, verify by:

1. Try pushing directly to `main` — it should be rejected
2. Open a PR to `main` — it should require CI checks to pass
3. Try force-pushing to `main` — it should be rejected

## GitHub Actions Status Checks

The required status check names come from the workflow job names:

| Workflow | Job name | Check name |
|----------|----------|------------|
| `backend-ci.yml` | `test` | `test` |
| `frontend-ci.yml` | `build` | `build` |
| `ci.yml` | `backend-quality` | `backend-quality` |
| `ci.yml` | `frontend-quality` | `frontend-quality` |

Add the check names from whichever CI workflow you're using. The checks must have run at least once before they appear in the branch protection dropdown.
