"use strict";

const crypto = require("crypto");
const helmet = require("helmet");

/**
 * Per-request CSP nonce + strict Content-Security-Policy.
 *
 * Design choices (see Project-2-Report.pdf for the full rationale):
 *  - default-src 'self'            deny-by-default for every fetch type
 *  - script-src 'self' 'nonce-…'   only our own files or a nonce-tagged
 *                                  inline <script> may run — NOT 'unsafe-inline',
 *                                  NOT 'unsafe-eval'. This alone blocks the
 *                                  attacker payloads in Project-2-Report.pdf,
 *                                  even if an escaping bug ever let markup
 *                                  through again (defense in depth).
 *  - object-src 'none'             blocks Flash/plugin-based injection vectors
 *  - base-uri 'self'                stops <base href> hijacking of relative URLs
 *  - frame-ancestors 'none'        clickjacking protection
 *  - upgrade-insecure-requests      belt-and-braces transport hardening
 *
 * The nonce is regenerated on every request (crypto.randomBytes), so it
 * cannot be guessed or replayed, and it is exposed on res.locals.cspNonce
 * so a template can tag its own trusted inline scripts with it.
 */
function nonceMiddleware(req, res, next) {
  res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
  next();
}

function buildCspMiddleware() {
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          (req, res) => `'nonce-${res.locals.cspNonce}'`,
        ],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    // Extra hardening headers bundled with helmet (X-Content-Type-Options,
    // X-Frame-Options, Referrer-Policy, etc.) stay on their defaults.
  });
}

module.exports = { nonceMiddleware, buildCspMiddleware };
