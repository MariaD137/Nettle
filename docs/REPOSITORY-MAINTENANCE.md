# Repository Maintenance

## Branch Strategy

```
main          ← Production (protected, PRs only)
develop       ← Integration / QA
feature/*     ← New features
fix/*         ← Bug fixes
hotfix/*      ← Emergency production fixes
release/*     ← Release preparation (when needed)
```

## Daily Workflows

### Start a new feature

```bash
git checkout develop
git pull --ff-only origin develop
git checkout -b feature/<name>

# Work on the feature...

git add <files>
git commit -m "feat: <description>"
git push -u origin feature/<name>
```

Open a PR: `feature/<name>` → `develop`

### Fix a bug

```bash
git checkout develop
git pull --ff-only origin develop
git checkout -b fix/<component>-<problem>

# Fix the bug...

git add <files>
git commit -m "fix: <description>"
git push -u origin fix/<component>-<problem>
```

Open a PR: `fix/<component>-<problem>` → `develop`

### Emergency production fix

```bash
git checkout main
git pull --ff-only origin main
git checkout -b hotfix/<problem>

# Fix the issue...

git add <files>
git commit -m "fix: <description>"
git push -u origin hotfix/<problem>
```

Open a PR: `hotfix/<problem>` → `main`

After merging the hotfix into main, bring it into develop:

```bash
git checkout develop
git pull --ff-only origin develop
git merge --no-ff main
git push origin develop
```

### Promote develop to production

```bash
# Open a PR: develop → main
# After CI passes and review is approved, merge
# This triggers the production deployment
```

## Running Tests Locally

```bash
# Backend
cd backend
npm test                    # Full suite (in-memory DB)
npm run lint                # TypeScript type check

# Individual test file
NETTLE_DB_PATH=:memory: node --import tsx --test test/scanner.test.ts

# Frontend
cd frontend
npm run lint                # TypeScript type check
npm run build               # Build check
```

## Running the App Locally

```bash
# Terminal 1 — Backend
cd backend
npm run dev                 # Starts on port 8080

# Terminal 2 — Frontend
cd frontend
npm run dev                 # Starts on port 5173
```

## Useful Git Commands

```bash
git status                  # See what's changed
git diff                    # See unstaged changes
git diff --staged           # See staged changes
git branch -a               # List all branches
git log --oneline -10       # Recent commit history
git fetch origin             # Update remote tracking
git stash -u                # Stash all changes (including untracked)
git stash pop               # Restore stashed changes
```

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat:     New feature
fix:      Bug fix
refactor: Code restructuring (no behavior change)
test:     Adding or updating tests
docs:     Documentation changes
chore:    Dependency updates, config changes
ci:       CI/CD workflow changes
build:    Build system changes
perf:     Performance improvements
```

Examples:

```bash
git commit -m "feat: add user dashboard page"
git commit -m "fix: resolve authentication timeout on slow networks"
git commit -m "refactor: extract scanner patterns into separate module"
git commit -m "test: add integration tests for billing webhook"
git commit -m "docs: update deployment guide with rollback steps"
git commit -m "ci: add security scanning to PR workflow"
```

## Handling Merge Conflicts

When a PR has conflicts:

```bash
git checkout <your-branch>
git fetch origin
git merge origin/develop    # or origin/main for hotfixes

# Resolve conflicts in your editor
# Look for <<<<<<< / ======= / >>>>>>> markers

git add <resolved-files>
git commit -m "fix: resolve merge conflicts with develop"
git push origin <your-branch>
```

If the conflict is complex or ambiguous, ask for help rather than guessing.

## Reverting a Change

```bash
# Revert the most recent commit
git revert HEAD

# Revert a specific commit
git revert <commit-sha>

# Push the revert
git push origin <branch>
```

Never use `git push --force` on `main` or `develop`.

## Cleaning Up Merged Branches

After a PR is merged, delete the feature/fix branch:

```bash
git branch -d feature/<name>           # Delete local branch
git push origin --delete feature/<name> # Delete remote branch
```
