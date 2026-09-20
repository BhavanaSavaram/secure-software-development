"use strict";

const request = require("supertest");
const { createApp } = require("../src/app");

describe("Content-Security-Policy", () => {
  const app = createApp();

  test("SECURE routes send a strict, deny-by-default CSP header", async () => {
    const res = await request(app).get("/secure/greet").query({ name: "Ada" });
    const csp = res.headers["content-security-policy"];

    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");

    // No blanket trust of inline/eval'd script.
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
  });

  test("the CSP script-src nonce changes on every request (not predictable/replayable)", async () => {
    const res1 = await request(app).get("/secure/greet");
    const res2 = await request(app).get("/secure/greet");

    const nonce1 = /'nonce-([^']+)'/.exec(res1.headers["content-security-policy"])[1];
    const nonce2 = /'nonce-([^']+)'/.exec(res2.headers["content-security-policy"])[1];

    expect(nonce1).toBeTruthy();
    expect(nonce2).toBeTruthy();
    expect(nonce1).not.toBe(nonce2);
  });

  test("VULNERABLE routes do not get the strict CSP (baseline for comparison)", async () => {
    const res = await request(app).get("/vulnerable/greet").query({ name: "Ada" });
    expect(res.headers["content-security-policy"]).toBeUndefined();
  });
});
