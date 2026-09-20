"use strict";

(function () {
  const params = new URLSearchParams(window.location.search);
  const query = params.get("q") || "";
  const results = document.getElementById("results");

  const input = document.getElementById("q");
  if (input) input.value = query;

  // FIX 1: plain-text echo uses textContent, not innerHTML. The string is
  // never parsed as HTML, so <img onerror=...> etc. is displayed as
  // literal characters instead of being executed.
  const line1 = document.createElement("p");
  line1.textContent = "You searched for: " + query;
  results.appendChild(line1);

  // FIX 2: a feature that legitimately needs to render *some* HTML (here:
  // bolding the search term inside a fixed sentence) sanitizes with
  // DOMPurify instead of either (a) trusting the input like the vulnerable
  // page does, or (b) giving up on the feature. DOMPurify strips event
  // handlers, <script>, javascript: URLs, etc. and only lets a safe
  // subset of markup through.
  const escapedForTemplate = query.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[
        c
      ])
  );
  const rawHtml = `Matched term: <strong>${escapedForTemplate}</strong>`;
  const sanitized = window.DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: ["strong", "em", "b", "i"],
    ALLOWED_ATTR: [],
  });

  const line2 = document.createElement("p");
  line2.innerHTML = sanitized;
  results.appendChild(line2);
})();
