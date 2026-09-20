"use strict";

/**
 * Safe arithmetic expression evaluator.
 *
 * This is the mitigation for the dynamic-evaluation vulnerability in
 * src/routes/vulnerable.js, which passes user input straight to eval().
 *
 * Instead of asking an interpreter (eval / new Function) to run arbitrary
 * attacker-supplied source, this is a small recursive-descent parser that
 * only understands numbers and + - * / ( ). There is no code path here
 * that can reach identifiers, property access, function calls, or any
 * other JavaScript language feature, so there is nothing for an attacker
 * to inject into: the grammar itself is the whitelist.
 *
 * Grammar:
 *   expression := term (("+" | "-") term)*
 *   term       := factor (("*" | "/") factor)*
 *   factor     := number | "(" expression ")" | ("-" | "+") factor
 */

class ExpressionError extends Error {}

function tokenize(input) {
  const tokens = [];
  const re = /\s*(?:(\d+(?:\.\d+)?)|([+\-*/()]))\s*/y;
  let pos = 0;
  while (pos < input.length) {
    re.lastIndex = pos;
    const match = re.exec(input);
    if (!match || match.index !== pos) {
      throw new ExpressionError(
        `Unexpected character at position ${pos}: "${input[pos]}"`
      );
    }
    if (match[1] !== undefined) {
      tokens.push({ type: "number", value: parseFloat(match[1]) });
    } else if (match[2] !== undefined) {
      tokens.push({ type: match[2], value: match[2] });
    }
    pos = re.lastIndex;
  }
  return tokens;
}

function parse(tokens) {
  let index = 0;

  const peek = () => tokens[index];
  const consume = (type) => {
    const tok = tokens[index];
    if (!tok || tok.type !== type) {
      throw new ExpressionError(
        `Expected "${type}" but got "${tok ? tok.type : "end of input"}"`
      );
    }
    index += 1;
    return tok;
  };

  function parseFactor() {
    const tok = peek();
    if (!tok) throw new ExpressionError("Unexpected end of expression");
    if (tok.type === "+" || tok.type === "-") {
      index += 1;
      const value = parseFactor();
      return tok.type === "-" ? -value : value;
    }
    if (tok.type === "number") {
      index += 1;
      return tok.value;
    }
    if (tok.type === "(") {
      index += 1;
      const value = parseExpression();
      consume(")");
      return value;
    }
    throw new ExpressionError(`Unexpected token "${tok.type}"`);
  }

  function parseTerm() {
    let value = parseFactor();
    while (peek() && (peek().type === "*" || peek().type === "/")) {
      const op = tokens[index].type;
      index += 1;
      const rhs = parseFactor();
      if (op === "*") {
        value *= rhs;
      } else {
        if (rhs === 0) throw new ExpressionError("Division by zero");
        value /= rhs;
      }
    }
    return value;
  }

  function parseExpression() {
    let value = parseTerm();
    while (peek() && (peek().type === "+" || peek().type === "-")) {
      const op = tokens[index].type;
      index += 1;
      const rhs = parseTerm();
      value = op === "+" ? value + rhs : value - rhs;
    }
    return value;
  }

  const result = parseExpression();
  if (index !== tokens.length) {
    throw new ExpressionError(`Unexpected trailing input at token ${index}`);
  }
  return result;
}

/**
 * Evaluate a plain arithmetic expression string. Throws ExpressionError
 * (never a raw SyntaxError/ReferenceError) on anything outside the
 * number / plus / minus / times / divide / parens grammar, including
 * identifiers, property access such as `process.env`, or template literals.
 */
function safeMathEval(input) {
  if (typeof input !== "string") {
    throw new ExpressionError("Expression must be a string");
  }
  if (input.length > 200) {
    throw new ExpressionError("Expression too long");
  }
  const tokens = tokenize(input);
  if (tokens.length === 0) {
    throw new ExpressionError("Empty expression");
  }
  return parse(tokens);
}

module.exports = { safeMathEval, ExpressionError };
