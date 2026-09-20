"use strict";

// UI glue shared by the vulnerable and secure calculator pages — makes a
// real fetch() POST to whichever endpoint the page's #calc-form declares
// in data-endpoint, and shows the real response. This script contains no
// vulnerability or fix of its own: everything security-relevant happens
// server-side, in src/routes/vulnerable.js / src/routes/secure.js.
(function () {
  const form = document.getElementById("calc-form");
  const input = document.getElementById("expression");
  const result = document.getElementById("result");
  const endpoint = form.dataset.endpoint;

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    result.textContent = "Calculating…";
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expression: input.value }),
      });
      const json = await res.json().catch(() => ({}));
      result.textContent = `HTTP ${res.status}\n${JSON.stringify(json, null, 2)}`;
    } catch (err) {
      result.textContent = "Request failed: " + err.message;
    }
  });
})();
