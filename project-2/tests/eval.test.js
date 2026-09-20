"use strict";

const request = require("supertest");
const { createApp } = require("../src/app");
const { INTERNAL_API_KEY } = require("../src/routes/vulnerable");

describe("Vulnerability 2a: dynamic evaluation via eval()", () => {
  const app = createApp();

  test("VULNERABLE /vulnerable/calculate performs legitimate arithmetic", async () => {
    const res = await request(app)
      .post("/vulnerable/calculate")
      .send({ expression: "2 + 3 * 4" });
    expect(res.status).toBe(200);
    expect(res.body.result).toBe(14);
  });

  test("VULNERABLE /vulnerable/calculate leaks data outside the intended scope via eval()", async () => {
    // eval() runs in the enclosing closure, so it can read variables the
    // API was never meant to expose to a client.
    const res = await request(app)
      .post("/vulnerable/calculate")
      .send({ expression: "INTERNAL_API_KEY" });

    expect(res.status).toBe(200);
    expect(res.body.result).toBe(INTERNAL_API_KEY);
  });

  test("VULNERABLE /vulnerable/calculate executes arbitrary JavaScript, not just math", async () => {
    const res = await request(app)
      .post("/vulnerable/calculate")
      .send({ expression: "(function(){ return 1+1===2 ? 'RCE-PROOF' : 'no'; })()" });

    expect(res.status).toBe(200);
    expect(res.body.result).toBe("RCE-PROOF");
  });

  test("SECURE /secure/calculate performs the same legitimate arithmetic", async () => {
    const res = await request(app)
      .post("/secure/calculate")
      .send({ expression: "2 + 3 * 4" });
    expect(res.status).toBe(200);
    expect(res.body.result).toBe(14);
  });

  test("SECURE /secure/calculate rejects the identifier-leak payload instead of evaluating it", async () => {
    const res = await request(app)
      .post("/secure/calculate")
      .send({ expression: "INTERNAL_API_KEY" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
    expect(JSON.stringify(res.body)).not.toContain(INTERNAL_API_KEY);
  });

  test("SECURE /secure/calculate rejects an IIFE / function-call payload", async () => {
    const res = await request(app)
      .post("/secure/calculate")
      .send({ expression: "(function(){ return 1; })()" });

    expect(res.status).toBe(400);
  });

  test("SECURE /secure/calculate rejects property-access payloads like process.env", async () => {
    const res = await request(app)
      .post("/secure/calculate")
      .send({ expression: "process.env" });

    expect(res.status).toBe(400);
  });
});

describe("Vulnerability 2b: dynamic evaluation via new Function()", () => {
  const app = createApp();

  test("VULNERABLE /vulnerable/format performs a legitimate custom formatter", async () => {
    const res = await request(app)
      .post("/vulnerable/format")
      .send({ formatter: "return n.toFixed(2);", value: 3.14159 });
    expect(res.status).toBe(200);
    expect(res.body.result).toBe("3.14");
  });

  test("VULNERABLE /vulnerable/format reaches Node internals via new Function()", async () => {
    const res = await request(app)
      .post("/vulnerable/format")
      .send({ formatter: "return typeof process;", value: 1 });
    expect(res.status).toBe(200);
    // The formatter body runs as real JS in (effectively) global scope,
    // so it can see Node globals a pure "format this number" feature
    // should never have access to.
    expect(res.body.result).toBe("object");
  });

  test("SECURE /secure/format only allows a fixed, named set of formatters", async () => {
    const res = await request(app)
      .post("/secure/format")
      .send({ formatterKey: "fixed2", value: 3.14159 });
    expect(res.status).toBe(200);
    expect(res.body.result).toBe(3.14);
  });

  test("SECURE /secure/format rejects arbitrary formatter source outright", async () => {
    const res = await request(app)
      .post("/secure/format")
      .send({ formatterKey: "return typeof process;", value: 1 });
    expect(res.status).toBe(400);
  });
});
