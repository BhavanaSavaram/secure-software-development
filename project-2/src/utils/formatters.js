"use strict";

// Fixed allowlist of number formatters, keyed by name. This replaces the
// "supply your own JS expression" formatter feature in the vulnerable
// route (src/routes/vulnerable.js `/format`) — see src/routes/secure.js.
module.exports = {
  fixed2: (n) => Number(n.toFixed(2)),
  percent: (n) => `${(n * 100).toFixed(1)}%`,
  rounded: (n) => Math.round(n),
  currencyUSD: (n) => `$${n.toFixed(2)}`,
};
