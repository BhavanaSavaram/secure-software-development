"use strict";

// Vendors the DOMPurify browser build into public/secure/vendor so the
// secure demo page can sanitize HTML client-side without a CDN dependency
// (which would also need to be added to the script-src CSP allowlist).
// Run automatically via the "postinstall" npm script.
const fs = require("fs");
const path = require("path");

const src = path.join(
  __dirname,
  "..",
  "node_modules",
  "dompurify",
  "dist",
  "purify.min.js"
);
const destDir = path.join(__dirname, "..", "public", "secure", "vendor");
const dest = path.join(destDir, "purify.min.js");

if (!fs.existsSync(src)) {
  console.warn("dompurify build not found at", src, "- skipping vendor copy");
  process.exit(0);
}

fs.mkdirSync(destDir, { recursive: true });
fs.copyFileSync(src, dest);
console.log("Vendored DOMPurify ->", path.relative(process.cwd(), dest));
