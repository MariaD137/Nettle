import fs from "fs";
import path from "path";

// `zip -r folder.zip folder/` (the common case) wraps every file in a single
// top-level directory. Scanning the extraction root directly then means every
// root-level check (package.json, privacy policy, lockfile) looks in the
// wrong place. Unwrap single-directory levels until we hit real content.
export function resolveScanRoot(dir: string): string {
  let current = dir;
  for (let i = 0; i < 5; i++) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    if (entries.length === 1 && entries[0].isDirectory()) {
      current = path.join(current, entries[0].name);
    } else {
      break;
    }
  }
  return current;
}
