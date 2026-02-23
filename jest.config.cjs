const path = require("path");

const config = {
  verbose: true,
  rootDir: __dirname,
  transform: {
    "^.+\\.ts$": "ts-jest",
    "node_modules/jose/.+\\.js$": "ts-jest", // Apply ts-jest to jose's js files
  },
  testEnvironment: "node",
  testRegex: "/tests/.*\\.(test|spec)\\.(ts|tsx)$",
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
  transformIgnorePatterns: ["node_modules/(?!(jose)/)"],
  moduleNameMapper: {
    "^@decaf-ts/core/ram$": "<rootDir>/node_modules/@decaf-ts/core/lib/ram/index.cjs",
  },
  collectCoverage: false,
  coverageDirectory: "./workdocs/reports/coverage",
  collectCoverageFrom: ["src/**/*.{js,jsx,ts,tsx}", "!src/bin/**/*"],
  reporters: ["default"],
  watchman: false,
};

module.exports = config;
