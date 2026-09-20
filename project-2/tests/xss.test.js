"use strict";

const request = require("supertest");
const { createApp } = require("../src/app");

describe("Vulnerability 1: reflected code injection via web application (XSS)", () => {
  const app = createApp();
  const PAYLOAD = "<script>alert(document.cookie)</script>";

  test("VULNERABLE /vulnerable/greet reflects <script> unescaped into the HTML response", async () => {
    const res = await request(app)
      .get("/vulnerable/greet")
      .query({ name: PAYLOAD });

    expect(res.status).toBe(200);
    // The raw, unescaped payload appears verbatim in the response body:
    // a browser parsing this response would execute it as a <script> tag.
    // (The page also shows a static, deliberately-escaped example of this
    // same payload in its own instructions, so we check the actual output
    // slot rather than asserting the whole document is free of "&lt;".)
    expect(res.text).toContain(PAYLOAD);
    expect(res.text).toContain(`Hello, ${PAYLOAD}!`);
  });

  test("SECURE /secure/greet renders the same payload as inert, escaped text", async () => {
    const res = await request(app)
      .get("/secure/greet")
      .query({ name: PAYLOAD });

    expect(res.status).toBe(200);
    // The dangerous characters are HTML-entity encoded, so the payload can
    // never be interpreted as markup by the browser. (escapeHtml also
    // encodes "/" as a defense-in-depth measure against "</script>" style
    // closing-tag breakouts, hence "&#x2F;" rather than a literal "/".)
    expect(res.text).not.toContain(PAYLOAD);
    expect(res.text).toContain(
      "&lt;script&gt;alert(document.cookie)&lt;&#x2F;script&gt;"
    );
  });

  test("SECURE /secure/greet still renders legitimate, non-malicious input correctly", async () => {
    const res = await request(app).get("/secure/greet").query({ name: "Ada" });
    expect(res.status).toBe(200);
    expect(res.text).toContain("Hello, Ada!");
  });

  // Reflected XSS isn't only a <script> tag: closing the surrounding
  // attribute/tag early and adding an event handler (onerror, onload, ...)
  // needs no <script> at all. A filter that only blocks the literal string
  // "<script>" would miss this entirely — the fix has to be encoding every
  // dangerous character, not pattern-matching known-bad payloads.
  const ATTR_PAYLOAD = `"><img src=x onerror=alert(document.cookie)>`;

  test("VULNERABLE /vulnerable/greet is also exploitable via attribute-breakout / event-handler payloads, not just <script>", async () => {
    const res = await request(app)
      .get("/vulnerable/greet")
      .query({ name: ATTR_PAYLOAD });

    expect(res.status).toBe(200);
    expect(res.text).toContain(ATTR_PAYLOAD);
  });

  test("SECURE /secure/greet escapes attribute-breakout and event-handler payloads too", async () => {
    const res = await request(app)
      .get("/secure/greet")
      .query({ name: ATTR_PAYLOAD });

    expect(res.text).not.toContain(`"><img src=x onerror=alert(document.cookie)>`);
    expect(res.text).toContain(
      "&quot;&gt;&lt;img src=x onerror=alert(document.cookie)&gt;"
    );
  });
});
