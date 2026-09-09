const path = require("path");

const config = {
  verbose: true,
  rootDir: __dirname,
  transform: {
    "^.+\\.ts$": "ts-jest",
    "node_modules/jose/.+\\.js$": "ts-jest", // Apply ts-jest to jose's js files
  },
  testEnvironment: "node",
  // PR-1 (SAA-1083) JwtService suites: unit (jwt-service.test.ts) +
  // integration (jwt-verify.test.ts, mock JWKS via tests/helpers/jwks.ts).
  // PR-2 (SAA-1084) cross-adapter matrix + platform-guard suites live under
  // tests/unit (cross-adapter-matrix.test.ts, cross-adapter-platform-guard.test.ts)
  // and are picked up by the standard tests/ pattern below.
  testRegex: "/tests/.*\\.(test|spec)\\.(ts|tsx)$",
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
  transformIgnorePatterns: ["node_modules/(?!(jose)/)"],
  moduleNameMapper: {
    "^@decaf-ts/core/ram$": "<rootDir>/node_modules/@decaf-ts/core/lib/cjs/ram/index.cjs",
  },
  collectCoverage: false,
  coverageDirectory: "./workdocs/reports/coverage",
  collectCoverageFrom: ["src/**/*.{js,jsx,ts,tsx}", "!src/bin/**/*"],
  reporters: ["default"],
  watchman: false,
};

module.exports = config;
