"use strict";

// DOM-based XSS sink: untrusted data (the URL) flows into innerHTML with
// no sanitization. See docs/VULNERABILITIES.md for the exploit walkthrough
// and public/secure/dom-safe.js for the fix.
(function () {
  const params = new URLSearchParams(window.location.search);
  const query = params.get("q") || "";
  const results = document.getElementById("results");

  // Pre-fill the search box with the current value. Assigning to .value is
  // always safe (it is never parsed as HTML), unlike the sink below.
  const input = document.getElementById("q");
  if (input) input.value = query;

  // VULNERABLE SINK: attacker-controlled string parsed as HTML/JS.
  results.innerHTML = "You searched for: " + query;
})();
