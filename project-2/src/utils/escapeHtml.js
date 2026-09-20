"use strict";

// Context-appropriate HTML-entity escaping for text inserted into an HTML
// document body. Order matters: '&' must be escaped first, or the entities
// produced for the other characters would themselves be re-escaped.
const HTML_ESCAPE_MAP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "/": "&#x2F;",
};

function escapeHtml(input) {
  if (input === null || input === undefined) return "";
  return String(input).replace(/[&<>"'/]/g, (ch) => HTML_ESCAPE_MAP[ch]);
}

module.exports = { escapeHtml };
