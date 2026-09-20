"use strict";

// Third dynamic-evaluation sink (alongside eval()/new Function() in
// src/routes/vulnerable.js): passing a STRING as setTimeout's callback.
// Per the HTML spec, browsers compile and run that string as JavaScript
// source the moment the timer fires — exactly like eval(), just delayed.
// See docs/VULNERABILITIES.md and public/secure/dynamic-timer-safe.js.
(function () {
  const params = new URLSearchParams(window.location.search);
  const run = params.get("run") || "document.getElementById('status').textContent = 'Timer fired (no payload given)';";

  const input = document.getElementById("run");
  if (input && params.has("run")) input.value = run;

  // VULNERABLE SINK: a string handed to setTimeout is implicitly eval()'d.
  setTimeout(run, 50);
})();
