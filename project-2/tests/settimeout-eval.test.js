"use strict";

/**
 * Third dynamic-evaluation vulnerability: setTimeout(callback, delay) with
 * a STRING callback. Per the HTML timers spec, browsers implicitly compile
 * and run that string as JavaScript when the timer fires — a delayed
 * eval(). Node.js's own setTimeout requires a real function and throws on
 * a string, so this is a browser-only sink and is verified here with a
 * real DOM (jsdom), not the default Node test environment.
 *
 * Mirrors public/vulnerable/dynamic-timer.js vs.
 * public/secure/dynamic-timer-safe.js; see Project-2-Report.pdf
 * for the full write-up.
 */

const { JSDOM } = require("jsdom");

function runTimers(window, ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

describe("Dynamic evaluation via setTimeout(string)", () => {
  test("VULNERABLE: a string handed to setTimeout is compiled and executed as JavaScript", async () => {
    const dom = new JSDOM("<!DOCTYPE html><div id=status></div>", {
      runScripts: "dangerously",
      url: "http://localhost/vulnerable/dynamic-timer.html",
    });
    const { window } = dom;
    window.__pwned = false;

    // Mirrors dynamic-timer.js's vulnerable sink exactly.
    const attackerPayload = "window.__pwned = true;";
    window.setTimeout(attackerPayload, 0);

    await runTimers(window, 20);
    expect(window.__pwned).toBe(true);
  });

  test("VULNERABLE: legitimate (non-malicious) string callbacks still work, which is why this bug hides in normal testing", async () => {
    const dom = new JSDOM("<!DOCTYPE html><div id=status></div>", {
      runScripts: "dangerously",
      url: "http://localhost/vulnerable/dynamic-timer.html",
    });
    const { window } = dom;

    window.setTimeout(
      "document.getElementById('status').textContent = 'ok';",
      0
    );
    await runTimers(window, 20);
    expect(window.document.getElementById("status").textContent).toBe("ok");
  });

  test("SECURE: the same string is only ever used as data, never executed", async () => {
    const dom = new JSDOM("<!DOCTYPE html><div id=status></div>", {
      runScripts: "dangerously",
      url: "http://localhost/secure/dynamic-timer-safe.html",
    });
    const { window } = dom;
    window.__pwned = false;

    const attackerPayload = "window.__pwned = true;";
    // Mirrors dynamic-timer-safe.js's fix: always a real function.
    window.setTimeout(function () {
      window.document.getElementById("status").textContent =
        "Timer fired. Message was: " + attackerPayload;
    }, 0);

    await runTimers(window, 20);
    expect(window.__pwned).toBe(false);
    expect(window.document.getElementById("status").textContent).toBe(
      "Timer fired. Message was: window.__pwned = true;"
    );
  });
});
