"use strict";

/**
 * Mitigated counterparts of src/routes/vulnerable.js. Each handler fixes
 * exactly one vulnerability described in Project-2-Report.pdf; see
 * that report for the reasoning behind each fix.
 */

const express = require("express");
const { escapeHtml } = require("../utils/escapeHtml");
const { safeMathEval, ExpressionError } = require("../utils/safeMathEval");
const FORMATTERS = require("../utils/formatters");

const router = express.Router();

/**
 * FIX for Vulnerability 1 (reflected XSS).
 *
 * Mitigation: output encoding. `name` is HTML-entity-escaped before it is
 * placed into the response body, so `<script>` arrives at the browser as
 * the literal text "&lt;script&gt;" and is rendered as visible text, never
 * parsed as an element. This is applied at the point of output (not on
 * input) because the same value could legitimately need different escaping
 * in a different context (HTML body vs. HTML attribute vs. JS string vs.
 * URL) — encode for the context you are writing into.
 *
 * A strict CSP (src/middleware/csp.js, mounted in src/app.js) is layered on
 * top as defense in depth: even if a future change reintroduced an
 * unescaped sink here, `script-src 'self' 'nonce-…'` would still stop an
 * injected <script> from executing, because it has neither our origin nor
 * a valid nonce.
 */
router.get("/greet", (req, res) => {
  const name = req.query.name || "friend";
  const safeName = escapeHtml(name);
  // Only the interpolation on the "Hello, ${safeName}!" line below carries
  // user input; everything else in this template (badge, form, styling) is
  // fixed markup.
  res.status(200).send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Secure Greeting</title>
        <link rel="stylesheet" href="/shared/styles.css" />
      </head>
      <body>
        <div class="card">
          <span class="badge secure">Secure</span>
          <h1>Greeting</h1>
          <p class="hint">
            Same feature as <code>/vulnerable/greet</code>, mitigated. Same
            payload, now inert:
            <code>&lt;script&gt;document.querySelector('.result').insertAdjacentHTML('beforeend','&lt;p&gt;&lt;strong&gt;STATUS: Malicious script executed.&lt;/strong&gt;&lt;/p&gt;')&lt;/script&gt;</code>
          </p>
          <form class="try-it" method="GET" action="/secure/greet">
            <label class="field-label visually-hidden" for="name">Name</label>
            <input type="text" id="name" name="name" placeholder="Your name..." autocomplete="off" />
            <button type="submit">Greet me</button>
          </form>
          <div class="result">
            <p class="result-heading">Hello, ${safeName}!</p>
          </div>
        </div>
      </body>
    </html>
  `);
});

/**
 * FIX for Vulnerability 2a (eval-based calculator).
 *
 * Mitigation: replace the interpreter call with a purpose-built parser
 * (src/utils/safeMathEval.js) whose grammar only accepts numbers and
 * + - * / ( ). There is no eval, no Function constructor, and no code path
 * that can reach identifiers — so there is no way to smuggle in
 * `process`, `require`, or a reference to INTERNAL_API_KEY. This is the
 * general pattern for "the feature only ever needed a small, fixed set of
 * operations" — least privilege applied to a language feature, not just to
 * a user account.
 */
router.post("/calculate", express.json(), (req, res) => {
  const { expression } = req.body || {};
  if (typeof expression !== "string") {
    return res.status(400).json({ error: "expression must be a string" });
  }
  try {
    const result = safeMathEval(expression);
    res.status(200).json({ result });
  } catch (err) {
    if (err instanceof ExpressionError) {
      return res.status(400).json({ error: err.message });
    }
    res.status(400).json({ error: "Invalid expression" });
  }
});

/**
 * FIX for Vulnerability 2b (Function-constructor formatter).
 *
 * Mitigation: replace "any expression the user wants" with an allowlist of
 * named, developer-written formatter functions. The client selects a
 * formatter by key (e.g. "fixed2", "percent"); the server looks the key up
 * in a fixed map instead of compiling client-supplied source at all. This
 * is the standard fix whenever "dynamic behavior" turns out to only need a
 * handful of variations — enumerate them instead of giving the client a
 * code-execution primitive.
 */
router.post("/format", express.json(), (req, res) => {
  const { formatterKey, value } = req.body || {};
  if (typeof formatterKey !== "string" || typeof value !== "number") {
    return res
      .status(400)
      .json({ error: "formatterKey must be a string and value a number" });
  }
  const fn = FORMATTERS[formatterKey];
  if (!fn) {
    return res.status(400).json({
      error: `Unknown formatterKey. Allowed: ${Object.keys(FORMATTERS).join(", ")}`,
    });
  }
  res.status(200).json({ result: fn(value) });
});

module.exports = { router };
