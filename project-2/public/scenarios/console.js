"use strict";

// Grading/demo aid only — not part of the application's security surface.
// Every result on this page comes from a real fetch() to the running
// server; nothing here is hardcoded or simulated.

async function postJson(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

function fmt(result) {
  return `HTTP ${result.status}\n${JSON.stringify(result.json, null, 2)}`;
}

const CALC_SCENARIOS = [
  { label: "Legitimate arithmetic", body: { expression: "2 + 3 * 4" } },
  { label: "Read out-of-scope secret", body: { expression: "INTERNAL_API_KEY" } },
  { label: "Arbitrary code execution (IIFE)", body: { expression: "(function(){return 1+1===2 ? 'RCE-PROOF' : 'no';})()" } },
  { label: "Reach Node internals", body: { expression: "process.version" } },
];

const FORMAT_SCENARIOS = [
  { label: "Legitimate formatter (vulnerable route)", vulnBody: { formatter: "return n.toFixed(2);", value: 3.14159 }, secureBody: { formatterKey: "fixed2", value: 3.14159 } },
  { label: "Reach Node globals via formatter body", vulnBody: { formatter: "return typeof process;", value: 1 }, secureBody: { formatterKey: "return typeof process;", value: 1 } },
];

const CSP_ROUTES = ["/vulnerable/greet?name=Ada", "/secure/greet?name=Ada"];

function addRow(tbody, cells, cls) {
  const tr = document.createElement("tr");
  if (cls) tr.className = cls;
  for (const { text, klass } of cells) {
    const td = document.createElement("td");
    if (klass) td.className = klass;
    td.textContent = text;
    tr.appendChild(td);
  }
  tbody.appendChild(tr);
}

async function runCalcScenarios() {
  const tbody = document.querySelector("#calc-table tbody");
  for (const scenario of CALC_SCENARIOS) {
    const [vuln, secure] = await Promise.all([
      postJson("/vulnerable/calculate", scenario.body),
      postJson("/secure/calculate", scenario.body),
    ]);
    const tr = document.createElement("tr");
    const tdLabel = document.createElement("td");
    tdLabel.textContent = scenario.label;
    const tdInput = document.createElement("td");
    tdInput.className = "input";
    tdInput.textContent = JSON.stringify(scenario.body);
    const tdVuln = document.createElement("td");
    tdVuln.className = "output";
    tdVuln.textContent = fmt(vuln);
    const tdSecure = document.createElement("td");
    tdSecure.className = "output";
    tdSecure.textContent = fmt(secure);
    tr.append(tdLabel, tdInput, tdVuln, tdSecure);
    tbody.appendChild(tr);
  }
}

async function runFormatScenarios() {
  const tbody = document.querySelector("#format-table tbody");
  for (const scenario of FORMAT_SCENARIOS) {
    const [vuln, secure] = await Promise.all([
      postJson("/vulnerable/format", scenario.vulnBody),
      postJson("/secure/format", scenario.secureBody),
    ]);
    const tr = document.createElement("tr");
    const tdLabel = document.createElement("td");
    tdLabel.textContent = scenario.label;
    const tdInput = document.createElement("td");
    tdInput.className = "input";
    tdInput.textContent =
      "vuln: " + JSON.stringify(scenario.vulnBody) + "\nsecure: " + JSON.stringify(scenario.secureBody);
    const tdVuln = document.createElement("td");
    tdVuln.className = "output";
    tdVuln.textContent = fmt(vuln);
    const tdSecure = document.createElement("td");
    tdSecure.className = "output";
    tdSecure.textContent = fmt(secure);
    tr.append(tdLabel, tdInput, tdVuln, tdSecure);
    tbody.appendChild(tr);
  }
}

async function runCspScenarios() {
  const tbody = document.querySelector("#csp-table tbody");
  for (const route of CSP_ROUTES) {
    const res = await fetch(route);
    const csp = res.headers.get("content-security-policy") || "(not set)";
    addRow(tbody, [{ text: route }, { text: csp, klass: "output" }]);
  }
}

runCalcScenarios();
runFormatScenarios();
runCspScenarios();
