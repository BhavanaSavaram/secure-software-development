"use strict";

const { safeMathEval, ExpressionError } = require("../src/utils/safeMathEval");

describe("safeMathEval (eval-free expression evaluator)", () => {
  test.each([
    ["2 + 2", 4],
    ["2 + 3 * 4", 14],
    ["(2 + 3) * 4", 20],
    ["10 / 4", 2.5],
    ["-5 + 3", -2],
    ["3.5 * 2", 7],
  ])("evaluates %s -> %s", (expr, expected) => {
    expect(safeMathEval(expr)).toBeCloseTo(expected);
  });

  test.each([
    "process.env",
    "require('fs')",
    "INTERNAL_API_KEY",
    "(function(){return 1;})()",
    "1; alert(1)",
    "`template`",
    "2 +",
    "",
    "2 / 0",
  ])("rejects non-arithmetic / malicious input: %s", (expr) => {
    expect(() => safeMathEval(expr)).toThrow(ExpressionError);
  });
});
