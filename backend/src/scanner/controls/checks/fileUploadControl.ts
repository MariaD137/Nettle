import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const FILE_UPLOAD_ANY_PATTERN = /multer|formidable|busboy|multipart|upload/i;
const SIZE_LIMIT_PATTERN = /fileSize|maxFileSize|fileSizeLimit|limits\s*:\s*\{[^}]*fileSize/i;
const TYPE_CHECK_PATTERN = /mimetype|mimeType|content-type.*check|fileFilter|allowedTypes|acceptedTypes/i;

/**
 * API-006, wired to the control library. Extracted from apiSecurity.ts's
 * former inline file-upload block -- same detection logic and
 * title/detail/remediation text, restructured as one CheckResult per
 * sub-check (size limit, type check), matching securityHeadersControl.ts's
 * multi-subcheck pattern, and to survive an unreadable file.
 */
export function scanFileUploadControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let allSource = "";
  let anyUnreadable = false;
  for (const file of jsFiles) {
    try {
      allSource += fs.readFileSync(file, "utf8") + "\n";
    } catch {
      anyUnreadable = true;
    }
  }

  const usesUpload = FILE_UPLOAD_ANY_PATTERN.test(allSource);
  if (!usesUpload) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("API Security", "API-006:unreadable"),
          status: "NOT_VERIFIED",
          category: "API Security",
          title: "Some files could not be read for file-upload analysis",
          detail: "No file upload handling was found in the files that could be read, but at least one file was unreadable and may have contained it.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "API-006",
        },
      ];
    }
    return []; // no file upload handling at all — nothing to check
  }

  const results: CheckResult[] = [];

  const hasSizeLimit = SIZE_LIMIT_PATTERN.test(allSource);
  if (hasSizeLimit) {
    results.push({
      checkId: generateCheckId("API Security", "API-006:pass:size"),
      status: "PASS",
      category: "API Security",
      title: "File uploads have a size limit configured",
      confidence: 70,
      detectionMethod: "heuristic",
      controlKey: "API-006",
    });
  } else if (!anyUnreadable) {
    results.push({
      checkId: generateCheckId("API Security", "API-006:fail:size"),
      status: "FAIL",
      category: "API Security",
      title: "File uploads without size limit",
      detail: "Without a file size limit, attackers can upload extremely large files to exhaust disk space or memory.",
      severity: "high",
      confidence: 70,
      detectionMethod: "heuristic",
      remediation: "Configure a file size limit in your upload middleware: multer({ limits: { fileSize: 5 * 1024 * 1024 } }) for a 5MB limit.",
      controlKey: "API-006",
    });
  } else {
    results.push({
      checkId: generateCheckId("API Security", "API-006:unreadable:size"),
      status: "NOT_VERIFIED",
      category: "API Security",
      title: "File uploads are used but not every file could be read to confirm a size limit",
      confidence: 0,
      detectionMethod: "heuristic",
      controlKey: "API-006",
    });
  }

  const hasTypeCheck = TYPE_CHECK_PATTERN.test(allSource);
  if (hasTypeCheck) {
    results.push({
      checkId: generateCheckId("API Security", "API-006:pass:type"),
      status: "PASS",
      category: "API Security",
      title: "File uploads have MIME type or extension validation",
      confidence: 70,
      detectionMethod: "heuristic",
      controlKey: "API-006",
    });
  } else if (!anyUnreadable) {
    results.push({
      checkId: generateCheckId("API Security", "API-006:fail:type"),
      status: "FAIL",
      category: "API Security",
      title: "File uploads without MIME type or extension validation",
      detail: "Without type checking, users can upload executable files (.exe, .sh, .php) that may be served or executed by the server.",
      severity: "high",
      confidence: 70,
      detectionMethod: "heuristic",
      remediation: "Add a file filter that checks MIME types and extensions: multer({ fileFilter: (req, file, cb) => { if (!allowedTypes.includes(file.mimetype)) return cb(new Error('Invalid type')); cb(null, true); } }).",
      controlKey: "API-006",
    });
  } else {
    results.push({
      checkId: generateCheckId("API Security", "API-006:unreadable:type"),
      status: "NOT_VERIFIED",
      category: "API Security",
      title: "File uploads are used but not every file could be read to confirm a type check",
      confidence: 0,
      detectionMethod: "heuristic",
      controlKey: "API-006",
    });
  }

  return results;
}
