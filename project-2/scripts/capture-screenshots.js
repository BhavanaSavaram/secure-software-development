"use strict";

/**
 * Captures real PNG screenshots of the running demo app for the coursework
 * submission. Not part of the application itself — a one-off dev script.
 *
 * Usage: node scripts/capture-screenshots.js
 * Requires the server to already be running (npm start / PORT=3100 node src/server.js).
 */

const path = require("path");
const fs = require("fs");
const { chromium } = require("playwright");

const BASE = process.env.BASE_URL || "http://localhost:3100";
const OUT_ROOT = path.join(__dirname, "..", "..");

const XSS_DIR = path.join(OUT_ROOT, "01-code-injection-via-web-applications", "screenshots");
const EVAL_DIR = path.join(OUT_ROOT, "02-dynamic-evaluation", "screenshots");
const CSP_DIR = path.join(OUT_ROOT, "03-mitigating-xss-and-csp", "screenshots");

for (const dir of [XSS_DIR, EVAL_DIR, CSP_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

// Every payload below only changes the page <title> and appends one plain
// status line INSIDE the page's own .result box — same box the calculator
// and formatter pages print their result into, and the same string a
// visitor is shown as the suggested "Try:" example on each page, so a
// screenshot, a live click-through, and the write-up all agree on what
// "it worked" looks like. No background-color changes, no alert() (which
// would block headless capture on a modal dialog). Using template literals
// (backticks) avoids the quote-escaping otherwise needed for the nested
// HTML attribute values.
const STATUS_HTML =
  "<p><strong>STATUS: Malicious script executed.</strong></p>";

const REFLECTED_PAYLOAD = `<script>document.title='XSS-EXECUTED';document.querySelector('.result').insertAdjacentHTML('beforeend','${STATUS_HTML}');</script>`;

const DOM_PAYLOAD = `<img src=x onerror="document.title='DOM-XSS-EXECUTED';document.querySelector('.result').insertAdjacentHTML('beforeend','${STATUS_HTML}');">`;

// Non-<script>-tag vector: an event-handler attribute on an <img>, proving
// the vulnerability isn't just "forgot to block <script>" — it's "wrote
// untrusted data into HTML at all."
const ATTR_PAYLOAD = `"><img src=x onerror="document.title='ATTR-XSS-EXECUTED';document.querySelector('.result').insertAdjacentHTML('beforeend','${STATUS_HTML}');">`;

// Third dynamic-evaluation sink: setTimeout(string) is a browser-only
// implicit eval(), distinct from eval()/new Function() (which are Node
// routes tested via the scenario console below).
const TIMER_PAYLOAD = `document.title='TIMER-EVAL-EXECUTED';document.querySelector('.result').insertAdjacentHTML('beforeend','${STATUS_HTML}');`;

async function shot(page, url, outfile, { waitMs = 300 } = {}) {
  await page.goto(url, { waitUntil: "load" });
  await page.waitForTimeout(waitMs);
  await page.screenshot({ path: outfile, fullPage: true });
  const title = await page.title();
  console.log(`saved ${path.relative(OUT_ROOT, outfile)}  (title: "${title}")`);
}

// For the calculator/formatter pages: real form fill + submit + wait for
// the fetch() response, then screenshot — same idea as `shot`, but for a
// page whose result appears via JS instead of a full navigation.
async function shotFormResult(page, url, { fill }, outfile) {
  await page.goto(url, { waitUntil: "load" });
  await fill(page);
  await page.waitForFunction(() => {
    const el = document.getElementById("result");
    return el && el.textContent !== "(no result yet)" && el.textContent !== "Calculating…";
  }, { timeout: 5000 });
  await page.waitForTimeout(150);
  await page.screenshot({ path: outfile, fullPage: true });
  const title = await page.title();
  console.log(`saved ${path.relative(OUT_ROOT, outfile)}  (title: "${title}")`);
}

async function main() {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1000, height: 650 } });

  // --- 1. Code injection via web applications ---------------------------
  await shot(
    page,
    `${BASE}/vulnerable/greet?name=${encodeURIComponent(REFLECTED_PAYLOAD)}`,
    path.join(XSS_DIR, "01-vulnerable-reflected-xss-executes.png")
  );
  await shot(
    page,
    `${BASE}/secure/greet?name=${encodeURIComponent(REFLECTED_PAYLOAD)}`,
    path.join(XSS_DIR, "02-secure-reflected-xss-neutralized.png")
  );
  await shot(
    page,
    `${BASE}/vulnerable/dom-xss.html?q=${encodeURIComponent(DOM_PAYLOAD)}`,
    path.join(XSS_DIR, "03-vulnerable-dom-xss-executes.png")
  );
  await shot(
    page,
    `${BASE}/secure/dom-safe.html?q=${encodeURIComponent(DOM_PAYLOAD)}`,
    path.join(XSS_DIR, "04-secure-dom-xss-neutralized.png")
  );
  await shot(
    page,
    `${BASE}/vulnerable/greet?name=${encodeURIComponent(ATTR_PAYLOAD)}`,
    path.join(XSS_DIR, "09-vulnerable-attribute-breakout-xss-executes.png")
  );
  await shot(
    page,
    `${BASE}/secure/greet?name=${encodeURIComponent(ATTR_PAYLOAD)}`,
    path.join(XSS_DIR, "10-secure-attribute-breakout-xss-neutralized.png")
  );

  // --- 2. Third dynamic-evaluation vector: setTimeout(string) -----------
  await shot(
    page,
    `${BASE}/vulnerable/dynamic-timer.html?run=${encodeURIComponent(TIMER_PAYLOAD)}`,
    path.join(EVAL_DIR, "11-vulnerable-settimeout-string-eval-executes.png"),
    { waitMs: 400 }
  );
  await shot(
    page,
    `${BASE}/secure/dynamic-timer-safe.html?run=${encodeURIComponent(TIMER_PAYLOAD)}`,
    path.join(EVAL_DIR, "12-secure-settimeout-neutralized.png"),
    { waitMs: 400 }
  );

  // --- 2. Calculator (eval()) and formatter (new Function()) pages ------
  await shotFormResult(
    page,
    `${BASE}/vulnerable/calculator.html`,
    {
      fill: async (p) => {
        await p.fill("#expression", "INTERNAL_API_KEY");
        await p.click("button[type=submit]");
      },
    },
    path.join(EVAL_DIR, "13-vulnerable-calculator-leaks-secret.png")
  );
  await shotFormResult(
    page,
    `${BASE}/secure/calculator.html`,
    {
      fill: async (p) => {
        await p.fill("#expression", "INTERNAL_API_KEY");
        await p.click("button[type=submit]");
      },
    },
    path.join(EVAL_DIR, "14-secure-calculator-rejects.png")
  );
  await shotFormResult(
    page,
    `${BASE}/vulnerable/formatter.html`,
    {
      fill: async (p) => {
        await p.fill("#value", "1");
        await p.fill("#code", "return typeof process;");
        await p.click("button[type=submit]");
      },
    },
    path.join(EVAL_DIR, "15-vulnerable-formatter-reaches-process.png")
  );
  await shotFormResult(
    page,
    `${BASE}/secure/formatter.html`,
    {
      fill: async (p) => {
        await p.fill("#value", "1");
        await p.fill("#code", "return typeof process;");
        await p.click("button[type=submit]");
      },
    },
    path.join(EVAL_DIR, "16-secure-formatter-rejects.png")
  );

  // --- 2 & 3. Dynamic evaluation + CSP mitigation (scenario console) -----
  await page.goto(`${BASE}/scenarios/console.html`, { waitUntil: "load" });
  // Wait for all fetch() scenarios on the page to finish populating tables.
  await page.waitForFunction(() => {
    const calc = document.querySelectorAll("#calc-table tbody tr").length;
    const fmt = document.querySelectorAll("#format-table tbody tr").length;
    const csp = document.querySelectorAll("#csp-table tbody tr").length;
    return calc >= 4 && fmt >= 2 && csp >= 2;
  }, { timeout: 15000 });
  await page.waitForTimeout(300);

  const calcTable = await page.$("#calc-table");
  await calcTable.screenshot({ path: path.join(EVAL_DIR, "05-eval-calculator-scenarios.png") });
  console.log(`saved ${path.relative(OUT_ROOT, path.join(EVAL_DIR, "05-eval-calculator-scenarios.png"))}`);

  const formatTable = await page.$("#format-table");
  await formatTable.screenshot({ path: path.join(EVAL_DIR, "06-function-constructor-scenarios.png") });
  console.log(`saved ${path.relative(OUT_ROOT, path.join(EVAL_DIR, "06-function-constructor-scenarios.png"))}`);

  const cspTable = await page.$("#csp-table");
  await cspTable.screenshot({ path: path.join(CSP_DIR, "07-csp-header-comparison.png") });
  console.log(`saved ${path.relative(OUT_ROOT, path.join(CSP_DIR, "07-csp-header-comparison.png"))}`);

  // Full console page too, for a single all-in-one artifact.
  await page.screenshot({
    path: path.join(EVAL_DIR, "08-full-scenario-console.png"),
    fullPage: true,
  });
  console.log(`saved ${path.relative(OUT_ROOT, path.join(EVAL_DIR, "08-full-scenario-console.png"))}`);

  await browser.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
