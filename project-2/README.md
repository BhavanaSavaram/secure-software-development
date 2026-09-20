# Code Injection and Dynamic Evaluation — Secure Software Development (Project 2)

A small Node.js / Express application that demonstrates JavaScript code-injection
vulnerabilities and their fixes side by side. Every feature exists twice: an
intentionally vulnerable version under `/vulnerable` and a mitigated version under
`/secure`, so the same input can be sent to both and the difference observed.

> **Warning:** the `/vulnerable` routes are deliberately insecure. Run the app on your
> own machine only. Never deploy it, and never copy these patterns into real code.

## What it demonstrates

| # | Scenario | Vulnerable | Fixed | Mitigation |
|---|---|---|---|---|
| 1 | Reflected XSS | `GET /vulnerable/greet?name=` | `GET /secure/greet?name=` | HTML-entity output encoding (`src/utils/escapeHtml.js`) |
| 2 | DOM-based XSS | `/vulnerable/dom-xss.html?q=` | `/secure/dom-safe.html?q=` | `textContent`, plus `DOMPurify.sanitize()` with a tag allowlist (`public/secure/dom-safe.js`) |
| 3 | Attribute / event-handler injection | `GET /vulnerable/greet?name=` | `GET /secure/greet?name=` | Same output encoding as #1 |
| 4 | `eval()` | `POST /vulnerable/calculate` (page: `/vulnerable/calculator.html`) | `POST /secure/calculate` (page: `/secure/calculator.html`) | Allowlist expression parser (`src/utils/safeMathEval.js`) |
| 5 | `Function` constructor | `POST /vulnerable/format` (page: `/vulnerable/formatter.html`) | `POST /secure/format` (page: `/secure/formatter.html`) | Fixed map of named formatters (`src/utils/formatters.js`) |
| 6 | `setTimeout(string)` | `/vulnerable/dynamic-timer.html?run=` | `/secure/dynamic-timer-safe.html?run=` | Always pass a function, never a string (`public/secure/dynamic-timer-safe.js`) |
| 7 | Content Security Policy | none | every `/secure` response | Strict policy with a per-request nonce (`src/middleware/csp.js`) |

## Requirements

- Node.js and npm (a current LTS release)
- Chromium through Playwright, only if you want to regenerate the screenshots (optional)

## Getting started

```bash
git clone https://github.com/BhavanaSavaram/secure-software-development.git
cd secure-software-development/project-2
npm install   # also vendors DOMPurify through a postinstall script
npm start     # http://localhost:3000
npm test      # runs the 41 tests
```

The server listens on port 3000 unless the `PORT` environment variable is set.

Open <http://localhost:3000> for a home page that links to every scenario. The page
`/scenarios/console.html` sends the same requests to the vulnerable and secure routes
and shows the real responses next to each other.

## Manual browser verification

With the server running, compare each vulnerable page with its secure counterpart.

| Scenario | Vulnerable route | Secure route |
|---|---|---|
| Reflected XSS | Open `/vulnerable/greet?name=<script>document.title='XSS-EXECUTED'</script>`. The tab title changes to `XSS-EXECUTED`. | Open the same query on `/secure/greet`. The payload appears as visible text and the title stays `Secure Greeting`. |
| DOM-based XSS | Open `/vulnerable/dom-xss.html?q=<img src=x onerror="document.title='DOM-XSS-EXECUTED'">`. The tab title changes. | Open the same query on `/secure/dom-safe.html`. The payload appears as literal text and the title does not change. |
| Attribute breakout | Open `/vulnerable/greet?name="><img src=x onerror="document.title='ATTR-XSS-EXECUTED'">`. The title changes even though there is no `<script>` tag. | Open the same query on `/secure/greet`. The payload appears as visible text. |
| `eval()` | On `/vulnerable/calculator.html`, enter `INTERNAL_API_KEY`. The server returns the secret value. | On `/secure/calculator.html`, enter the same input. The request is rejected with a `400` error. |
| `Function` constructor | On `/vulnerable/formatter.html`, enter the formatter body `return typeof process;`. The result is `object`. | On `/secure/formatter.html`, enter the same input. The request is rejected and the allowed formatter names are listed. |
| `setTimeout(string)` | Open `/vulnerable/dynamic-timer.html?run=document.title='TIMER-EVAL-EXECUTED'`. About 50 ms later the title changes. | Open the same query on `/secure/dynamic-timer-safe.html`. The payload appears as text and nothing runs. |

## Automated tests

`npm test` runs Jest with Supertest and jsdom. Tests inside a "VULNERABLE" describe block are
expected to show the exploit succeeding; that is the executable proof the weakness is real.

| Suite | Tests | What it checks |
|---|---|---|
| `tests/xss.test.js` | 5 | The reflected XSS payload is returned unescaped by `/vulnerable/greet` and escaped by `/secure/greet` |
| `tests/dom-injection.test.js` | 4 | `innerHTML` creates a live element from the payload, `textContent` does not, and `DOMPurify.sanitize()` strips the dangerous parts |
| `tests/eval.test.js` | 11 | `eval()` and `new Function()` run arbitrary code (including leaking the out-of-scope secret) and the fixed routes reject the same payloads |
| `tests/safeMathEval.test.js` | 15 | The eval-free parser computes valid arithmetic and rejects every non-arithmetic input |
| `tests/csp.test.js` | 3 | The policy directives are present, `unsafe-inline` and `unsafe-eval` are absent, and the nonce changes on every request |
| `tests/settimeout-eval.test.js` | 3 | `setTimeout(string, delay)` is compiled and run as code, and passing a real function fixes it |

## Project layout

```
project-2/
├── src/
│   ├── app.js                  Express app: mounts the vulnerable and secure sides
│   ├── server.js               Starts the server
│   ├── routes/
│   │   ├── vulnerable.js       Intentionally vulnerable endpoints
│   │   └── secure.js           Fixed counterparts
│   ├── middleware/csp.js       Per-request nonce and strict Content-Security-Policy
│   └── utils/                  escapeHtml.js, safeMathEval.js, formatters.js
├── public/
│   ├── home/                   Landing page linking to every scenario
│   ├── vulnerable/             DOM XSS, calculator, formatter and timer pages
│   ├── secure/                 Fixed versions of those pages
│   ├── scenarios/              Side-by-side console
│   └── shared/                 Shared styles and page scripts
├── tests/                      Jest suites (41 tests)
├── scripts/
│   ├── copy-dompurify.js       Postinstall step that vendors DOMPurify
│   └── capture-screenshots.js  Optional screenshot generator
├── jest.config.js
└── package.json
```

## Regenerating screenshots (optional)

```bash
npx playwright install chromium   # first run only
PORT=3100 node src/server.js &
node scripts/capture-screenshots.js
```

The script drives a real headless Chromium through each scenario and saves PNG files into
`screenshots` folders one level above this project folder, creating them if needed. A headless
browser has no window frame, so the script adds a bar at the top of each image showing the
requested URL; everything below that bar is the application's own output.

## License

MIT (see `package.json`).
