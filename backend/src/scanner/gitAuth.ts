import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

/**
 * The askpass script's content. Kept as a separate, directly-testable pure
 * function: git invokes this script with the credential prompt text as
 * argv[1] ("Username for '...'" or "Password for '...'") and reads whatever
 * it prints on stdout. The actual token is read from the script's own
 * environment (NETTLE_GIT_TOKEN) rather than being embedded in the script
 * text or the repo URL — so it never appears in `git clone`'s argv (visible
 * to `ps`) or in git's own error output if the clone fails.
 *
 * "x-access-token" as the username is GitHub's documented convention for
 * PAT-over-HTTPS; GitLab and Bitbucket both accept an arbitrary username
 * alongside a token/app-password, so the same script works for all three
 * hosts this route allows.
 */
export function buildAskpassScript(): string {
  return [
    "#!/bin/sh",
    'case "$1" in',
    "  Username*) echo \"x-access-token\" ;;",
    '  *) echo "$NETTLE_GIT_TOKEN" ;;',
    "esac",
    "",
  ].join("\n");
}

/**
 * Clones `repoUrl` into `cloneDir`, authenticating with `token` when one is
 * given. The token is passed to the child process's environment, never as a
 * command-line argument and never embedded in the URL — both of those would
 * leak it into `ps` output or into git's own error messages on failure.
 */
export function cloneRepo(repoUrl: string, branch: string, cloneDir: string, token?: string | null): void {
  const args = ["clone", "--depth", "1"];
  if (branch) args.push("--branch", branch);
  args.push(repoUrl, cloneDir);

  if (!token) {
    execFileSync("git", args, { timeout: 60_000, stdio: "pipe" });
    return;
  }

  const askpassDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-askpass-"));
  const askpassPath = path.join(askpassDir, "askpass.sh");
  try {
    fs.writeFileSync(askpassPath, buildAskpassScript(), { mode: 0o700 });
    execFileSync("git", args, {
      timeout: 60_000,
      stdio: "pipe",
      env: {
        ...process.env,
        GIT_ASKPASS: askpassPath,
        GIT_TERMINAL_PROMPT: "0",
        NETTLE_GIT_TOKEN: token,
      },
    });
  } finally {
    fs.rmSync(askpassDir, { recursive: true, force: true });
  }
}
