"use strict";

// UI glue shared by the vulnerable and secure formatter pages — makes a
// real fetch() POST to whichever endpoint the page's #format-form declares
// in data-endpoint, using whichever field name (data-field: "formatter" or
// "formatterKey") that endpoint actually expects. This script contains no
// vulnerability or fix of its own: everything security-relevant happens
// server-side, in src/routes/vulnerable.js / src/routes/secure.js.
(function () {
  const form = document.getElementById("format-form");
  const endpoint = form.dataset.endpoint;
  const fieldName = form.dataset.field;
  const valueInput = document.getElementById("value");
  const codeInput = document.getElementById("code");
  const result = document.getElementById("result");

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    result.textContent = "Formatting…";
    const body = { value: Number(valueInput.value) };
    body[fieldName] = codeInput.value;
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const json = await res.json().catch(() => ({}));
      result.textContent = `HTTP ${res.status}\n${JSON.stringify(json, null, 2)}`;
    } catch (err) {
      result.textContent = "Request failed: " + err.message;
    }
  });
})();
