"use strict";

const path = require("path");
const express = require("express");

const { router: vulnerableRouter } = require("./routes/vulnerable");
const { router: secureRouter } = require("./routes/secure");
const { nonceMiddleware, buildCspMiddleware } = require("./middleware/csp");

function createApp() {
  const app = express();

  // --- Shared, purely presentational CSS reused by every demo page (both
  // vulnerable and secure). Same-origin, so it satisfies the secure pages'
  // style-src 'self' CSP without any special-casing.
  app.use(
    "/shared",
    express.static(path.join(__dirname, "..", "public", "shared"))
  );

  // --- Vulnerable side: no CSP, no output encoding, eval-based endpoints.
  // Mounted first and with no security middleware, deliberately, so the
  // exploits in docs/VULNERABILITIES.md work exactly as described.
  app.use("/vulnerable", vulnerableRouter);
  app.use(
    "/vulnerable",
    express.static(path.join(__dirname, "..", "public", "vulnerable"))
  );

  // --- Secure side: strict CSP + nonce on every response, output encoding,
  // no eval/Function-constructor anywhere in the request path.
  app.use(nonceMiddleware, buildCspMiddleware());
  app.use("/secure", secureRouter);
  app.use(
    "/secure",
    express.static(path.join(__dirname, "..", "public", "secure"))
  );

  // --- Scenario console: a grading/demo aid, not part of the app's
  // security surface. It only makes fetch() calls to the routes above and
  // displays their real responses; mounted outside the CSP block purely so
  // its own small inline console isn't gated by a policy meant for the
  // secure app, not for this harness.
  app.use(
    "/scenarios",
    express.static(path.join(__dirname, "..", "public", "scenarios"))
  );

  app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "..", "public", "home", "index.html"));
  });

  return app;
}

module.exports = { createApp };
