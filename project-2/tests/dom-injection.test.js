"use strict";

/**
 * Verifies the client-side (DOM-based) XSS sink used in
 * public/vulnerable/dom-xss.js vs. the fix in public/secure/dom-safe.js,
 * using a real DOM (jsdom) instead of the browser. See Project-2-Report.pdf;
 * manual browser verification steps are in README.md.
 */

const { JSDOM } = require("jsdom");
const createDOMPurify = require("dompurify");

const PAYLOAD = '<img src=x onerror="window.__pwned = true">';

describe("DOM-based XSS sink: innerHTML vs. textContent", () => {
  test("VULNERABLE sink: innerHTML parses attacker HTML into real, executable elements", () => {
    const dom = new JSDOM(`<!DOCTYPE html><div id="results"></div>`);
    const { document } = dom.window;
    const results = document.getElementById("results");

    // Mirrors public/vulnerable/dom-xss.js: results.innerHTML = "..." + query
    results.innerHTML = "You searched for: " + PAYLOAD;

    const img = results.querySelector("img");
    expect(img).not.toBeNull();
    expect(img.getAttribute("onerror")).toBe("window.__pwned = true");
    // In a real browser, the failed image load fires onerror and runs the
    // attacker's JS. jsdom doesn't fetch images, but the element (and its
    // live event-handler attribute) existing at all is the vulnerability:
    // the string was parsed as markup, not displayed as text.
  });

  test("SECURE sink: textContent renders the same payload as inert text, no elements created", () => {
    const dom = new JSDOM(`<!DOCTYPE html><div id="results"></div>`);
    const { document } = dom.window;
    const results = document.getElementById("results");

    // Mirrors public/secure/dom-safe.js FIX 1.
    results.textContent = "You searched for: " + PAYLOAD;

    expect(results.querySelector("img")).toBeNull();
    expect(results.textContent).toBe("You searched for: " + PAYLOAD);
    expect(results.innerHTML).not.toContain("<img");
  });
});

describe("DOM-based XSS sink: DOMPurify.sanitize for legitimate rich-text output", () => {
  const window = new JSDOM("").window;
  const DOMPurify = createDOMPurify(window);

  test("strips <img onerror>, <script>, and event-handler attributes", () => {
    const dirty = `Matched term: <strong>${PAYLOAD}</strong><script>window.__pwned2 = true</script>`;
    const clean = DOMPurify.sanitize(dirty, {
      ALLOWED_TAGS: ["strong", "em", "b", "i"],
      ALLOWED_ATTR: [],
    });

    expect(clean).not.toContain("onerror");
    expect(clean).not.toContain("<script>");
    expect(clean).not.toContain("<img");
    expect(clean).toContain("<strong>");
  });

  test("still allows the intended formatting tag through", () => {
    const clean = DOMPurify.sanitize("<strong>hello</strong>", {
      ALLOWED_TAGS: ["strong"],
      ALLOWED_ATTR: [],
    });
    expect(clean).toBe("<strong>hello</strong>");
  });
});
