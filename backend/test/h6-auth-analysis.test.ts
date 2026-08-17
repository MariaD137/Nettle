import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeAuth, getAuthSeverity, generateAuthRemediation } from "../src/scanner/authAnalysis";
import type { RouteInfo } from "../src/scanner/authAnalysis";

test("H-6: Express route with no auth is detected", () => {
  const code = `
    const express = require('express');
    const app = express();

    app.get('/api/users', (req, res) => {
      res.json({ users: [] });
    });
  `;

  const result = analyzeAuth(code);
  assert.equal(result.framework, "express");
  assert.ok(result.unprotectedRoutes.length > 0);
});

test("H-6: Express route with auth middleware is protected", () => {
  const code = `
    const express = require('express');
    const app = express();

    app.get('/api/admin', verifyJWT, (req, res) => {
      res.json({ data: 'secret' });
    });
  `;

  const result = analyzeAuth(code);
  assert.equal(result.framework, "express");
  assert.equal(result.unprotectedRoutes.length, 0);
});

test("H-6: Multiple Express routes analyzed", () => {
  const code = `const express = require('express');
const app = express();
app.get('/public', (req, res) => res.send('public'));
app.post('/create', verifyJWT, (req, res) => res.send('created'));
app.delete('/delete/:id', (req, res) => res.send('deleted'));`;

  const result = analyzeAuth(code);
  assert.ok(result.routesAnalyzed >= 2, `expected at least 2 routes, got ${result.routesAnalyzed}`);
  assert.ok(result.unprotectedRoutes.length >= 1);
});

test("H-6: Django function-based view with login_required is protected", () => {
  const code = `
    from django.contrib.auth.decorators import login_required

    @login_required
    def user_profile(request):
        return render(request, 'profile.html')
  `;

  const result = analyzeAuth(code, "django");
  assert.equal(result.framework, "django");
  assert.equal(result.unprotectedRoutes.length, 0);
});

test("H-6: Django view without decorator is unprotected", () => {
  const code = `def public_page(request):
    return render(request, 'public.html')
def admin_dashboard(request):
    return render(request, 'admin.html')`;

  const result = analyzeAuth(code, "django");
  assert.ok(result.unprotectedRoutes.length >= 1, `expected at least 1 unprotected route, got ${result.unprotectedRoutes.length}`);
});

test("H-6: Flask route with login_required is protected", () => {
  const code = `
    from flask import Flask
    from flask_login import login_required

    @app.route('/admin')
    @login_required
    def admin():
        return 'Admin dashboard'
  `;

  const result = analyzeAuth(code, "flask");
  assert.equal(result.framework, "flask");
  assert.equal(result.unprotectedRoutes.length, 0);
});

test("H-6: Flask route without auth is unprotected", () => {
  const code = `
    from flask import Flask

    @app.route('/api/data', methods=['GET', 'POST'])
    def get_data():
        return jsonify(data=[])
  `;

  const result = analyzeAuth(code, "flask");
  assert.ok(result.unprotectedRoutes.length > 0);
});

test("H-6: FastAPI route with Depends is protected", () => {
  const code = `
    from fastapi import FastAPI, Depends

    @app.get('/protected')
    def get_protected(token: str = Depends(oauth2_scheme)):
        return {'data': 'secret'}
  `;

  const result = analyzeAuth(code, "fastapi");
  assert.equal(result.unprotectedRoutes.length, 0);
});

test("H-6: POST without auth is critical severity", () => {
  const route: RouteInfo = {
    path: "/api/users",
    method: "POST",
    isProtected: false,
    detectionMethod: "none",
  };

  assert.equal(getAuthSeverity(route), "critical");
});

test("H-6: DELETE without auth is critical severity", () => {
  const route: RouteInfo = {
    path: "/api/users/:id",
    method: "DELETE",
    isProtected: false,
    detectionMethod: "none",
  };

  assert.equal(getAuthSeverity(route), "critical");
});

test("H-6: PUT without auth is critical severity", () => {
  const route: RouteInfo = {
    path: "/api/users/:id",
    method: "PUT",
    isProtected: false,
    detectionMethod: "none",
  };

  assert.equal(getAuthSeverity(route), "critical");
});

test("H-6: GET without auth is medium severity", () => {
  const route: RouteInfo = {
    path: "/api/public-data",
    method: "GET",
    isProtected: false,
    detectionMethod: "none",
  };

  assert.equal(getAuthSeverity(route), "medium");
});

test("H-6: Remediation for Express", () => {
  const route: RouteInfo = {
    path: "/api/data",
    method: "POST",
    isProtected: false,
    detectionMethod: "none",
  };

  const remedy = generateAuthRemediation(route, "express");
  assert.ok(remedy.includes("verifyJWT"));
  assert.ok(remedy.includes("/api/data"));
});

test("H-6: Remediation for Django", () => {
  const route: RouteInfo = {
    path: "api_view",
    method: "POST",
    isProtected: false,
    detectionMethod: "none",
  };

  const remedy = generateAuthRemediation(route, "django");
  assert.ok(remedy.includes("@login_required"));
});

test("H-6: Remediation for Flask", () => {
  const route: RouteInfo = {
    path: "/admin",
    method: "GET",
    isProtected: false,
    detectionMethod: "none",
  };

  const remedy = generateAuthRemediation(route, "flask");
  assert.ok(remedy.includes("@login_required"));
});

test("H-6: Remediation for FastAPI", () => {
  const route: RouteInfo = {
    path: "/api/protected",
    method: "GET",
    isProtected: false,
    detectionMethod: "none",
  };

  const remedy = generateAuthRemediation(route, "fastapi");
  assert.ok(remedy.includes("Depends"));
});

test("H-6: Framework detection from imports", () => {
  const expressCode = "const express = require('express');";
  const djangoCode = "from django.http import HttpResponse";
  const flaskCode = "from flask import Flask";
  const fastApiCode = "from fastapi import FastAPI";

  assert.equal(analyzeAuth(expressCode).framework, "express");
  assert.equal(analyzeAuth(djangoCode, undefined).framework, "django");
  assert.equal(analyzeAuth(flaskCode, undefined).framework, "flask");
  assert.equal(analyzeAuth(fastApiCode, undefined).framework, "fastapi");
});

test("H-6: Confidence reflects route coverage", () => {
  const code = `
    const app = express();
    app.get('/api/users', (req, res) => res.json([]));
    app.get('/api/posts', (req, res) => res.json([]));
  `;

  const result = analyzeAuth(code);
  assert.ok(result.confidence > 0);
  assert.ok(result.confidence <= 100);
});

test("H-6: Router objects are analyzed", () => {
  const code = `
    const express = require('express');
    const router = express.Router();

    router.get('/items', (req, res) => res.json([]));
    router.post('/items', verifyAuth, (req, res) => res.json({}));
  `;

  const result = analyzeAuth(code);
  assert.equal(result.routesAnalyzed, 2);
});
