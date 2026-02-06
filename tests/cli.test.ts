import { Command } from "commander";
import createCliProgram from "../src/cli-module";
import fs from "fs";
import { CryptoKey } from "../src/common"; // Assuming CryptoKey is exported from common

// Mock cryptographic functions and modules
jest.mock("../src/common/crypto", () => ({
  getSubtle: jest.fn(() => ({
    encrypt: jest.fn(async (alg, key, data) =>
      new TextEncoder().encode("encrypted-" + new TextDecoder().decode(data))
    ),
    decrypt: jest.fn(async (alg, key, data) =>
      new TextEncoder().encode(
        new TextDecoder().decode(data).replace("encrypted-", "")
      )
    ),
    importKey: jest.fn(
      async (format, keyData, alg, ext, usages) => ({}) as CryptoKey
    ),
  })),
}));

jest.mock("../src/common/index", () => ({
  ...jest.requireActual("../src/common/index"),
  CryptoKey: {} as CryptoKey, // Mock CryptoKey
  AlgorithmIdentifier: {}, // Mock AlgorithmIdentifier
  KeyUsage: [], // Mock KeyUsage
  AesGcmParams: {}, // Mock AesGcmParams
  Algorithm: {}, // Mock Algorithm
}));

// Mock fs module
jest.mock("fs", () => ({
  ...jest.requireActual("fs"),
  readFileSync: jest.fn(),
  writeFileSync: jest.fn(),
}));

// Mock console.log and process.exit
const mockLog = jest.spyOn(console, "log").mockImplementation(() => {});
const mockError = jest.spyOn(console, "error").mockImplementation(() => {});
const mockProcessExit = jest
  .spyOn(process, "exit")
  .mockImplementation((() => {}) as any);

describe.skip("Crypto CLI", () => {
  let program: Command;

  beforeEach(() => {
    program = new Command();
    program.addCommand(createCliProgram());
    mockLog.mockClear();
    mockError.mockClear();
    mockProcessExit.mockClear();
    (fs.readFileSync as jest.Mock).mockClear();
    (fs.writeFileSync as jest.Mock).mockClear();
  });

  afterAll(() => {
    mockLog.mockRestore();
    mockError.mockRestore();
    mockProcessExit.mockRestore();
  });

  describe("encrypt command", () => {
    const secret = "test-secret";
    const algorithm = "AES-GCM";
    const keyLength = "256";

    it("should encrypt --data to console", async () => {
      const testData = "hello world";
      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "encrypt",
          "--data",
          testData,
          "--secret",
          secret,
          "--alg",
          algorithm,
          "--key-length",
          keyLength,
        ],
        { from: "user" }
      );
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining("encrypted-")
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should encrypt --data to --out file", async () => {
      const testData = "hello world";
      const outFile = "output.txt";
      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "encrypt",
          "--data",
          testData,
          "--out",
          outFile,
          "--secret",
          secret,
          "--alg",
          algorithm,
          "--key-length",
          keyLength,
        ],
        { from: "user" }
      );
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        outFile,
        expect.stringContaining("encrypted-")
      );
      expect(mockLog).toHaveBeenCalledWith(
        `Encrypted content written to ${outFile}.`
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should encrypt --file in place", async () => {
      const inFile = "input.txt";
      const fileContent = "file content";
      (fs.readFileSync as jest.Mock).mockReturnValue(fileContent);

      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "encrypt",
          "--file",
          inFile,
          "--secret",
          secret,
          "--alg",
          algorithm,
          "--key-length",
          keyLength,
        ],
        { from: "user" }
      );
      expect(fs.readFileSync).toHaveBeenCalledWith(inFile, "utf-8");
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        inFile,
        expect.stringContaining("encrypted-file content")
      );
      expect(mockLog).toHaveBeenCalledWith(
        `File ${inFile} encrypted in place.`
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should encrypt --file to --out file", async () => {
      const inFile = "input.txt";
      const outFile = "output.txt";
      const fileContent = "file content";
      (fs.readFileSync as jest.Mock).mockReturnValue(fileContent);

      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "encrypt",
          "--file",
          inFile,
          "--out",
          outFile,
          "--secret",
          secret,
          "--alg",
          algorithm,
          "--key-length",
          keyLength,
        ],
        { from: "user" }
      );
      expect(fs.readFileSync).toHaveBeenCalledWith(inFile, "utf-8");
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        outFile,
        expect.stringContaining("encrypted-file content")
      );
      expect(mockLog).toHaveBeenCalledWith(
        `Encrypted content written to ${outFile}.`
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should exit with error if --secret is missing", async () => {
      await program.parseAsync(
        ["node", "test", "crypto", "encrypt", "--data", "test"],
        { from: "user" }
      );
      expect(mockError).toHaveBeenCalledWith(
        "Error: --secret is required for encryption."
      );
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });

    it("should exit with error if no input source is provided", async () => {
      await program.parseAsync(
        ["node", "test", "crypto", "encrypt", "--secret", secret],
        { from: "user" }
      );
      expect(mockError).toHaveBeenCalledWith(
        "Error: One of --file or --data must be provided."
      );
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });

    it("should exit with error if both --file and --data are provided", async () => {
      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "encrypt",
          "--file",
          "f.txt",
          "--data",
          "d",
          "--secret",
          secret,
        ],
        { from: "user" }
      );
      expect(mockError).toHaveBeenCalledWith(
        "Error: Only one of --file or --data can be provided."
      );
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });

    it("should exit with error on encryption failure", async () => {
      (
        require("../src/common/crypto").getSubtle as jest.Mock
      ).mockImplementationOnce(() => ({
        encrypt: jest.fn(() => Promise.reject(new Error("Encryption error"))),
        decrypt: jest.fn(),
        importKey: jest.fn(() => ({}) as CryptoKey),
      }));
      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "encrypt",
          "--data",
          "test",
          "--secret",
          secret,
        ],
        { from: "user" }
      );
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining("Encryption failed: Encryption error")
      );
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });
  });

  describe("decrypt command", () => {
    const secret = "test-secret";
    const algorithm = "AES-GCM";
    const keyLength = "256";

    it("should decrypt --data to console", async () => {
      const encryptedData = "encrypted-hello world";
      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "decrypt",
          "--data",
          encryptedData,
          "--secret",
          secret,
          "--alg",
          algorithm,
          "--key-length",
          keyLength,
        ],
        { from: "user" }
      );
      expect(mockLog).toHaveBeenCalledWith("hello world");
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should decrypt --data to --out file", async () => {
      const encryptedData = "encrypted-hello world";
      const outFile = "output.txt";
      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "decrypt",
          "--data",
          encryptedData,
          "--out",
          outFile,
          "--secret",
          secret,
          "--alg",
          algorithm,
          "--key-length",
          keyLength,
        ],
        { from: "user" }
      );
      expect(fs.writeFileSync).toHaveBeenCalledWith(outFile, "hello world");
      expect(mockLog).toHaveBeenCalledWith(
        `Decrypted content written to ${outFile}.`
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should decrypt --file in place", async () => {
      const inFile = "input.txt";
      const fileContent = "encrypted-file content";
      (fs.readFileSync as jest.Mock).mockReturnValue(fileContent);

      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "decrypt",
          "--file",
          inFile,
          "--secret",
          secret,
          "--alg",
          algorithm,
          "--key-length",
          keyLength,
        ],
        { from: "user" }
      );
      expect(fs.readFileSync).toHaveBeenCalledWith(inFile, "utf-8");
      expect(fs.writeFileSync).toHaveBeenCalledWith(inFile, "file content");
      expect(mockLog).toHaveBeenCalledWith(
        `File ${inFile} decrypted in place.`
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should decrypt --file to --out file", async () => {
      const inFile = "input.txt";
      const outFile = "output.txt";
      const fileContent = "encrypted-file content";
      (fs.readFileSync as jest.Mock).mockReturnValue(fileContent);

      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "decrypt",
          "--file",
          inFile,
          "--out",
          outFile,
          "--secret",
          secret,
          "--alg",
          algorithm,
          "--key-length",
          keyLength,
        ],
        { from: "user" }
      );
      expect(fs.readFileSync).toHaveBeenCalledWith(inFile, "utf-8");
      expect(fs.writeFileSync).toHaveBeenCalledWith(outFile, "file content");
      expect(mockLog).toHaveBeenCalledWith(
        `Decrypted content written to ${outFile}.`
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should exit with error if --secret is missing", async () => {
      await program.parseAsync(
        ["node", "test", "crypto", "decrypt", "--data", "encrypted-test"],
        { from: "user" }
      );
      expect(mockError).toHaveBeenCalledWith(
        "Error: --secret is required for decryption."
      );
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });

    it("should exit with error if no input source is provided", async () => {
      await program.parseAsync(
        ["node", "test", "crypto", "decrypt", "--secret", secret],
        { from: "user" }
      );
      expect(mockError).toHaveBeenCalledWith(
        "Error: One of --file or --data must be provided."
      );
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });

    it("should exit with error if both --file and --data are provided", async () => {
      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "decrypt",
          "--file",
          "f.txt",
          "--data",
          "d",
          "--secret",
          secret,
        ],
        { from: "user" }
      );
      expect(mockError).toHaveBeenCalledWith(
        "Error: Only one of --file or --data can be provided."
      );
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });

    it("should exit with error on decryption failure", async () => {
      (
        require("../src/common/crypto").getSubtle as jest.Mock
      ).mockImplementationOnce(() => ({
        encrypt: jest.fn(),
        decrypt: jest.fn(() => Promise.reject(new Error("Decryption error"))),
        importKey: jest.fn(() => ({}) as CryptoKey),
      }));
      await program.parseAsync(
        [
          "node",
          "test",
          "crypto",
          "decrypt",
          "--data",
          "encrypted-test",
          "--secret",
          secret,
        ],
        { from: "user" }
      );
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining("Decryption failed: Decryption error")
      );
      expect(mockProcessExit).toHaveBeenCalledWith(1);
    });
  });
});
