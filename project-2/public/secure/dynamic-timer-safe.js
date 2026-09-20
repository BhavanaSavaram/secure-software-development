"use strict";

// FIX for the setTimeout-string sink in public/vulnerable/dynamic-timer.js.
// setTimeout's first argument is always a real function, so there is no
// code path where the browser compiles user input as JavaScript. Whatever
// the caller supplied is only ever handed to textContent (data, not code).
(function () {
  const params = new URLSearchParams(window.location.search);
  const run = params.get("run") || "(no payload given)";

  const input = document.getElementById("run");
  if (input && params.has("run")) input.value = run;

  // FIX: a real function reference, never a string.
  setTimeout(function () {
    document.getElementById("status").textContent =
      "Timer fired. Message was: " + run;
  }, 50);
})();
