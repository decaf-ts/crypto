import { Config } from "@jest/types";

const config: Config.InitialOptions = {
  verbose: true,
  rootDir: __dirname,
  transform: {
    "^.+\\.ts?$": "ts-jest",
    "node_modules/jose/.+\\.js$": "ts-jest", // Apply ts-jest to jose's js files
  },
  testEnvironment: "node",
  testRegex: "/tests/.*\\.(test|spec)\\.(ts|tsx)$",
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
  transformIgnorePatterns: ["node_modules/(?!(jose)/)"],
  collectCoverage: false,
  coverageDirectory: "./workdocs/reports/coverage",
  collectCoverageFrom: ["src/**/*.{js,jsx,ts,tsx}", "!src/bin/**/*"],
  reporters: ["default"],
};

export default config;
