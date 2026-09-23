import type { Control } from "../types";
import { registerControl } from "../registry";

export const INPUT_004: Control = {
  controlKey: "INPUT-004",
  category: "Security",
  subcategory: "Command injection",
  name: "No shell command built via string interpolation",
  description:
    "Building a shell command with a template literal or string concatenation and passing it to exec() risks " +
    "command injection if any interpolated value comes from user input — the shell interprets metacharacters " +
    "(;, |, &&, $(...)) in whatever gets substituted in, turning a single injected argument into an arbitrary " +
    "additional command.",
  question: "Are shell commands built without interpolating values into a single command string?",
  defaultSeverity: "critical",

  passCriteria: "No call to child_process.exec()/exec() with an interpolated template literal or string-concatenated command was found (verified via AST).",
  failCriteria: "A call to child_process.exec()/exec() was found where the command string is built via template-literal interpolation.",
  notVerifiedCriteria: "Semgrep (the AST analysis engine this check depends on) was not available, so command construction was not checked.",

  whyItMatters:
    "exec() hands its argument to a shell, which parses it for metacharacters before running it. Interpolating a " +
    "value into that string — even one that looks safe — means an attacker who controls that value can terminate " +
    "the intended command and chain their own. execFile()/spawn() with an explicit argument array never invoke a " +
    "shell to parse the arguments, which removes this entire injection class rather than requiring it to be " +
    "sanitized away.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Use execFile()/spawn() with an arguments array instead of exec() with a single interpolated command string.",
      developerFix: "Replace child_process.exec(`cmd ${arg}`) with child_process.execFile('cmd', [arg]) — the argument array is passed directly to the program, never through a shell, so shell metacharacters in arg have no special meaning.",
      architectureFix: "If a shell feature (pipes, globbing) is genuinely required, validate the interpolated value against a strict allowlist before it reaches the command string, rather than relying on ad hoc escaping.",
      codeExample: "// Instead of: exec(`convert ${filename} out.png`)\nexecFile('convert', [filename, 'out.png']);",
    },
  ],

  longTermHardening: "Add an ESLint rule or a Semgrep CI gate that fails the build on exec() called with a non-literal, interpolated command string.",
  verificationMethod: "Rescan and confirm the exec() call now uses execFile()/spawn() with an argument array, or that no interpolated command string remains.",
  references: ["OWASP: OS Command Injection"],
  complianceMappings: [],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(INPUT_004);
