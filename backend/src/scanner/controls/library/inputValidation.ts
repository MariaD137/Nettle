import type { Control } from "../types";
import { registerControl } from "../registry";

export const API_004: Control = {
  controlKey: "API-004",
  category: "API Security",
  subcategory: "Request validation",
  name: "Schema validation on request bodies",
  description:
    "A route that accepts a request body should validate its shape before using it — without that, the handler " +
    "trusts whatever the caller sends, which leads to type confusion, injection, and undefined behavior further " +
    "down the call stack.",
  question: "Are request bodies validated against a schema before use?",
  defaultSeverity: "medium",

  passCriteria: "A schema-validation library (Zod, Joi, Yup, express-validator, Ajv, superstruct) is referenced in the scanned source.",
  failCriteria: "The application defines routes that accept a body (POST/PUT/PATCH) but no schema-validation library was found anywhere in the scanned source.",
  notVerifiedCriteria: "No route accepting a request body was found in the scanned source, so there is nothing this control applies to.",

  whyItMatters:
    "An unvalidated request body is attacker-controlled input flowing directly into business logic, database queries, " +
    "or downstream services. Type confusion (a string where a number was assumed), unexpected fields, and malformed " +
    "nested structures are a common source of both crashes and injection.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "npm install zod, then validate the body at the top of each handler: const parsed = schema.parse(req.body).",
      developerFix: "Define a schema per route and validate before any business logic runs. Zod and Joi both give clear validation error messages that are safe to return to the client.",
      architectureFix: "Apply validation as middleware bound to each route (a validateBody(schema) helper), so a new route can't skip it and the handler body only ever sees validated data.",
      codeExample: "const schema = z.object({ email: z.string().email(), age: z.number().int().positive() });\napp.post('/users', (req, res) => {\n  const body = schema.parse(req.body); // throws on invalid input\n  ...\n});",
    },
    {
      technology: "fastapi",
      quickFix: "Declare the request body as a Pydantic model parameter — FastAPI validates it automatically before the handler runs.",
      developerFix: "Use a Pydantic BaseModel for every request body; FastAPI rejects an invalid body with a 422 before your code executes.",
      codeExample: "class CreateUser(BaseModel):\n    email: EmailStr\n    age: PositiveInt\n\n@app.post('/users')\ndef create_user(body: CreateUser): ...",
    },
    {
      technology: "generic",
      quickFix: "Add a schema-validation library and validate every request body before it reaches business logic.",
      developerFix: "Define a schema per endpoint that accepts a body, and reject the request with a 4xx before any handler logic runs on unvalidated data.",
      architectureFix: "Apply validation as shared middleware/decorator on the route, not as ad hoc checks scattered through handler code.",
    },
  ],

  longTermHardening: "Add tests asserting each endpoint rejects a malformed body (wrong type, missing required field, unexpected extra field) with a 4xx, not a 500.",
  verificationMethod: "Rescan and confirm a schema-validation library is now present in the source.",
  references: ["OWASP Input Validation Cheat Sheet"],
  complianceMappings: ["SOC 2 CC6.1"],

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

registerControl(API_004);
