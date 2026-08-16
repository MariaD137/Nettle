import fs from "fs";
import path from "path";

/**
 * Detect frameworks in the analyzed codebase.
 * Used to provide framework-aware remediation and guidance.
 */

export interface FrameworkDetectionResult {
  detected: string[];
  primaryFramework: string | null;
  confidence: number; // 0-100
  detectionMethod: string[]; // what files/patterns we checked
}

interface FrameworkSignature {
  name: string;
  packageNames: string[];
  configFiles: string[];
  patterns: string[]; // patterns to search in source code
}

const FRAMEWORK_SIGNATURES: FrameworkSignature[] = [
  {
    name: "next.js",
    packageNames: ["next"],
    configFiles: ["next.config.js", "next.config.ts", ".next"],
    patterns: ["getServerSideProps", "getStaticProps", "getStaticPaths"],
  },
  {
    name: "react",
    packageNames: ["react"],
    configFiles: [],
    patterns: ["useState", "useEffect", "React.FC"],
  },
  {
    name: "express",
    packageNames: ["express"],
    configFiles: [],
    patterns: ["app.get", "app.post", "express.Router"],
  },
  {
    name: "nuxt",
    packageNames: ["nuxt"],
    configFiles: ["nuxt.config.ts", "nuxt.config.js", ".nuxt"],
    patterns: ["defineNuxtComponent", "useAsyncData", "useFetch"],
  },
  {
    name: "fastapi",
    packageNames: ["fastapi"],
    configFiles: [],
    patterns: ["@app.get", "@app.post", "FastAPI()"],
  },
  {
    name: "django",
    packageNames: ["django"],
    configFiles: ["settings.py", "urls.py", "wsgi.py"],
    patterns: ["@login_required", "views.py", "models.Model"],
  },
  {
    name: "flask",
    packageNames: ["flask"],
    configFiles: [],
    patterns: ["@app.route", "Flask(__name__)", "from flask import"],
  },
  {
    name: "vue",
    packageNames: ["vue"],
    configFiles: ["vue.config.js"],
    patterns: ["<template>", "export default {", "defineComponent"],
  },
  {
    name: "svelte",
    packageNames: ["svelte"],
    configFiles: ["svelte.config.js"],
    patterns: [".svelte"],
  },
  {
    name: "astro",
    packageNames: ["astro"],
    configFiles: ["astro.config.mjs", "astro.config.ts"],
    patterns: ["---", "@astrojs"],
  },
  {
    name: "remix",
    packageNames: ["@remix-run/react"],
    configFiles: ["remix.config.js"],
    patterns: ["useLoaderData", "useActionData"],
  },
  {
    name: "angular",
    packageNames: ["@angular/core"],
    configFiles: ["angular.json"],
    patterns: ["@Component", "@Injectable", "NgModule"],
  },
  {
    name: "tailwind",
    packageNames: ["tailwindcss"],
    configFiles: ["tailwind.config.js", "tailwind.config.ts"],
    patterns: ["@tailwind", "className=\""],
  },
  {
    name: "typescript",
    packageNames: ["typescript"],
    configFiles: ["tsconfig.json"],
    patterns: [".ts", ".tsx"],
  },
];

export function detectFrameworks(projectRoot: string, packageJson?: any, sourceFiles?: string[]): FrameworkDetectionResult {
  const detected = new Set<string>();
  const methods = new Set<string>();
  let confidence = 0;

  // Parse package.json if provided (usually already parsed by caller)
  let pkg: any = packageJson;
  if (!pkg && fs.existsSync(path.join(projectRoot, "package.json"))) {
    try {
      const content = fs.readFileSync(path.join(projectRoot, "package.json"), "utf8");
      pkg = JSON.parse(content);
      methods.add("package.json");
    } catch {
      // Couldn't parse, skip
    }
  }

  // Check for config files
  for (const sig of FRAMEWORK_SIGNATURES) {
    for (const configFile of sig.configFiles) {
      const fullPath = path.join(projectRoot, configFile);
      if (fs.existsSync(fullPath)) {
        detected.add(sig.name);
        methods.add(`${configFile}`);
        confidence = Math.min(100, confidence + 30);
      }
    }
  }

  // Check package.json dependencies
  if (pkg?.dependencies || pkg?.devDependencies) {
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    for (const sig of FRAMEWORK_SIGNATURES) {
      for (const pkgName of sig.packageNames) {
        if (allDeps[pkgName]) {
          detected.add(sig.name);
          methods.add("package.json");
          confidence = Math.min(100, confidence + 20);
        }
      }
    }
  }

  // Check source file patterns (if available)
  if (sourceFiles && sourceFiles.length > 0) {
    for (const sig of FRAMEWORK_SIGNATURES) {
      for (const pattern of sig.patterns) {
        for (const file of sourceFiles) {
          try {
            const content = fs.readFileSync(file, "utf8");
            if (content.includes(pattern)) {
              detected.add(sig.name);
              methods.add("source patterns");
              confidence = Math.min(100, confidence + 15);
              break; // Found pattern, move to next sig
            }
          } catch {
            // Couldn't read file, skip
          }
        }
      }
    }
  }

  // Determine primary framework (the one with the highest confidence)
  let primaryFramework: string | null = null;
  if (detected.size > 0) {
    // Framework precedence: infrastructure (Next, Nuxt) > libraries (Express, Django)
    const priority: Record<string, number> = {
      "next.js": 10,
      nuxt: 10,
      remix: 9,
      django: 8,
      fastapi: 8,
      express: 7,
      flask: 7,
      react: 6,
      vue: 6,
      svelte: 6,
      angular: 6,
      astro: 5,
      tailwind: 1,
      typescript: 1,
    };

    primaryFramework = Array.from(detected).sort((a, b) => (priority[b] ?? 0) - (priority[a] ?? 0))[0];
  }

  return {
    detected: Array.from(detected),
    primaryFramework,
    confidence: Math.max(0, Math.min(100, confidence)),
    detectionMethod: Array.from(methods),
  };
}
