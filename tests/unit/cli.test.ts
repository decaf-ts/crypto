import { Command } from "commander";
import createCliProgram from "../../src/cli-module";
import * as os from "os";
import * as path from "path";
import { Obfuscation } from "../../src/node/Obfuscation";
import { encryptContent, decryptContent, getDerivedKey } from "../../src/common/utils";
import { getSubtle } from "../../src/common/crypto";

// Mock fs module to allow spying on its methods without "Cannot redefine property" errors
jest.mock("fs", () => {
  const actualFs = jest.requireActual("fs") as typeof import("fs");
  const spiedFs = {
    ...actualFs,
    readFileSync: jest.fn(actualFs.readFileSync),
    writeFileSync: jest.fn(actualFs.writeFileSync),
    unlinkSync: jest.fn(actualFs.unlinkSync),
    existsSync: jest.fn(actualFs.existsSync),
    statSync: jest.fn(actualFs.statSync),
    readdirSync: jest.fn(actualFs.readdirSync),
    mkdirSync: jest.fn(actualFs.mkdirSync),
    rmSync: jest.fn(actualFs.rmSync),
  };
  return spiedFs;
});

// Access the spied functions from the mocked fs module
const fs = jest.requireMock("fs") as typeof import("fs") & {
  readFileSync: jest.Mock;
  writeFileSync: jest.Mock;
  unlinkSync: jest.Mock;
  existsSync: jest.Mock;
  statSync: jest.Mock;
  readdirSync: jest.Mock;
  mkdirSync: jest.Mock;
  rmSync: jest.Mock;
};

// Mock console.log and process.exit
const mockLog = jest.spyOn(console, "log").mockImplementation(() => {});
const mockError = jest.spyOn(console, "error").mockImplementation(() => {});
const mockProcessExit = jest
  .spyOn(process, "exit")
  .mockImplementation((code?: number) => {
    throw new Error(`process.exit: ${code || 0}`);
  });

describe("Crypto CLI", () => {
  let program: Command;
  let tempDir: string;

  // Helper to create files in tempDir
  const createTestFile = (relativePath: string, content: string): string => {
    const filePath = path.join(tempDir, relativePath);
    fs.mkdirSync(path.dirname(filePath), { recursive: true }); // Ensure parent directory exists
    fs.writeFileSync(filePath, content);
    return filePath;
  };

  // Helper to create a directory in tempDir
  const createTestDir = (relativePath: string): string => {
    const dirPath = path.join(tempDir, relativePath);
    fs.mkdirSync(dirPath, { recursive: true });
    return dirPath;
  };

  // Helper to create obfuscated files in tempDir
  const createObfuscatedFile = (
    relativePath: string,
    originalContent: string,
    secret: string
  ): string => {
    const originalFilePath = path.join(tempDir, relativePath);
    const obfuscatedFilePath = `${originalFilePath}.enc`;
    fs.mkdirSync(path.dirname(originalFilePath), { recursive: true }); // Ensure parent directory exists
    const obfuscatedBuffer = Obfuscation.obfuscate(
      secret,
      Buffer.from(originalContent)
    );
    fs.writeFileSync(obfuscatedFilePath, obfuscatedBuffer);
    return obfuscatedFilePath;
  };

  beforeEach(() => {
    // Create a unique temporary directory for each test
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "crypto-cli-test-"));

    program = createCliProgram();
    mockLog.mockClear();
    mockError.mockClear();
    mockProcessExit.mockClear();

    // Clear previous mock calls on the spied fs functions
    fs.readFileSync.mockClear();
    fs.writeFileSync.mockClear();
    fs.unlinkSync.mockClear();
    fs.existsSync.mockClear();
    fs.statSync.mockClear();
    fs.readdirSync.mockClear();
    fs.mkdirSync.mockClear();
    fs.rmSync.mockClear();
  });

  afterEach(() => {
    // Clean up the temporary directory
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  afterAll(() => {
    // Restore global console mocks once after all tests
    mockLog.mockRestore();
    mockError.mockRestore();
    mockProcessExit.mockRestore();
  });

  describe("encrypt command", () => {
    const secret = "test-secret-key-for-aes256-ok!!!" // exactly 32 bytes for AES-256
    const algorithm = "AES-GCM";
    const keyLength = "256";

    it("should encrypt --data to console", async () => {
      const testData = "hello world";
      await program.parseAsync(
        [
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
      expect(mockLog).toHaveBeenCalledWith(expect.any(String)); // Should be a hex string
      const loggedHex = mockLog.mock.calls[0][0];

      // Verify that the logged output can be decrypted to the original data
      const subtle = await getSubtle();
      const derivedKey = await getDerivedKey(subtle, secret, algorithm, parseInt(keyLength, 10), ["encrypt", "decrypt"]);
      const decrypted = await decryptContent(subtle, derivedKey, algorithm, loggedHex);
      expect(decrypted).toBe(testData);
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should encrypt --data to --out file", async () => {
      const testData = "hello world";
      const outFile = path.join(tempDir, "output.txt");
      await program.parseAsync(
        [
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
      expect(fs.writeFileSync).toHaveBeenCalledWith(outFile, expect.any(String)); // Should write a hex string
      const writtenHex = fs.readFileSync(outFile, "utf8");
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Encrypted content written to ${outFile}.`)
      );

      // Verify that the written content can be decrypted to the original data
      const subtle = await getSubtle();
      const derivedKey = await getDerivedKey(subtle, secret, algorithm, parseInt(keyLength, 10), ["encrypt", "decrypt"]);
      const decrypted = await decryptContent(
        subtle,
        derivedKey,
        algorithm,
        writtenHex
      );
      expect(decrypted).toBe(testData);
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should encrypt --file in place", async () => {
      const inFile = path.join(tempDir, "input.txt");
      const fileContent = "file content";
      fs.writeFileSync(inFile, fileContent); // Create the actual file

      await program.parseAsync(
        [
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
      // Check the SECOND call to writeFileSync (the one from the CLI)
      expect(fs.writeFileSync.mock.calls[1][0]).toBe(inFile);
      expect(fs.writeFileSync.mock.calls[1][1]).toEqual(expect.any(String)); // Should write a hex string
      const writtenHex = fs.readFileSync(inFile, "utf8");
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Encrypted content written to ${inFile}.`)
      );
      // Verify that the written content can be decrypted to the original data
      const subtle = await getSubtle();
      const derivedKey = await getDerivedKey(subtle, secret, algorithm, parseInt(keyLength, 10), ["encrypt", "decrypt"]);
      const decrypted = await decryptContent(
        subtle,
        derivedKey,
        algorithm,
        writtenHex
      );
      expect(decrypted).toBe(fileContent);
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should encrypt --file to --out file", async () => {
      const inFile = path.join(tempDir, "input.txt");
      const outFile = path.join(tempDir, "output.txt");
      const fileContent = "file content";
      fs.writeFileSync(inFile, fileContent); // Create the actual input file

      await program.parseAsync(
        [
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
      // Check the SECOND call to writeFileSync (the one from the CLI writing to outFile)
      expect(fs.writeFileSync.mock.calls[1][0]).toBe(outFile);
      expect(fs.writeFileSync.mock.calls[1][1]).toEqual(expect.any(String)); // Should write a hex string
      const writtenHex = fs.readFileSync(outFile, "utf8");
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Encrypted content written to ${outFile}.`)
      );
      // Verify that the written content can be decrypted to the original data
      const subtle = await getSubtle();
      const derivedKey = await getDerivedKey(subtle, secret, algorithm, parseInt(keyLength, 10), ["encrypt", "decrypt"]);
      const decrypted = await decryptContent(
        subtle,
        derivedKey,
        algorithm,
        writtenHex
      );
      expect(decrypted).toBe(fileContent);
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should exit with error if --secret is missing", async () => {
      await expect(
        program.parseAsync(["encrypt", "--data", "test"], { from: "user" })
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining("Error: --secret is required for encryption.")
      );
    });

    it("should exit with error if no input source is provided", async () => {
      await expect(
        program.parseAsync(["encrypt", "--secret", secret], { from: "user" })
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining(
          "Error: One of --file or --data must be provided."
        )
      );
    });

    it("should exit with error if both --file and --data are provided", async () => {
      const fTxtPath = createTestFile("f.txt", "dummy content"); // Create the dummy file
      await expect(
        program.parseAsync(
          ["encrypt", "--file", fTxtPath, "--data", "d", "--secret", secret],
          { from: "user" }
        )
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining(
          "Error: Only one of --file or --data can be provided."
        )
      );
    });

    it("should exit with error on encryption failure", async () => {
      // Use an invalid algorithm to trigger a real encryption error
      await expect(
        program.parseAsync(
          ["encrypt", "--data", "test", "--secret", secret, "--alg", "INVALID-ALG"],
          { from: "user" }
        )
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalled();
    });
  });

  describe("decrypt command", () => {
    const secret = "test-secret-key-for-aes256-ok!!!" // exactly 32 bytes for AES-256
    const algorithm = "AES-GCM";
    const keyLength = "256";

    it("should decrypt --data to console", async () => {
      const originalData = "hello world";
      const subtle = await getSubtle();
      const derivedKey = await getDerivedKey(subtle, secret, algorithm, parseInt(keyLength, 10), ["encrypt", "decrypt"]);
      const encryptedData = await encryptContent(
        subtle,
        derivedKey, // Use derivedKey here
        algorithm,
        originalData
      );
      await program.parseAsync(
        [
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
      expect(mockLog).toHaveBeenCalledWith(originalData);
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should decrypt --data to --out file", async () => {
      const originalData = "hello world";
      const subtle = await getSubtle();
      const derivedKey = await getDerivedKey(subtle, secret, algorithm, parseInt(keyLength, 10), ["encrypt", "decrypt"]);
      const encryptedData = await encryptContent(
        subtle,
        derivedKey, // Use derivedKey here
        algorithm,
        originalData
      );
      const outFile = path.join(tempDir, "output.txt");
      await program.parseAsync(
        [
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
      expect(fs.writeFileSync).toHaveBeenCalledWith(outFile, originalData);
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Decrypted content written to ${outFile}.`)
      );
      expect(fs.readFileSync(outFile, "utf8")).toBe(originalData); // Verify actual file content
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should decrypt --file in place", async () => {
      const originalContent = "file content";
      const subtle = await getSubtle();
      const derivedKey = await getDerivedKey(subtle, secret, algorithm, parseInt(keyLength, 10), ["encrypt", "decrypt"]);
      const encryptedFileContent = await encryptContent(
        subtle,
        derivedKey, // Use derivedKey here
        algorithm,
        originalContent
      );
      const inFile = path.join(tempDir, "input.txt");
      fs.writeFileSync(inFile, encryptedFileContent); // Create the actual encrypted file

      await program.parseAsync(
        [
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
      expect(fs.writeFileSync).toHaveBeenCalledWith(inFile, originalContent);
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Decrypted content written to ${inFile}.`)
      );
      expect(fs.readFileSync(inFile, "utf8")).toBe(originalContent); // Verify actual file content
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should decrypt --file to --out file", async () => {
      const originalContent = "file content";
      const subtle = await getSubtle();
      const derivedKey = await getDerivedKey(subtle, secret, algorithm, parseInt(keyLength, 10), ["encrypt", "decrypt"]);
      const encryptedFileContent = await encryptContent(
        subtle,
        derivedKey, // Use derivedKey here
        algorithm,
        originalContent
      );
      const inFile = path.join(tempDir, "input.txt");
      const outFile = path.join(tempDir, "output.txt");
      fs.writeFileSync(inFile, encryptedFileContent); // Create the actual encrypted input file

      await program.parseAsync(
        [
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
      expect(fs.writeFileSync).toHaveBeenCalledWith(outFile, originalContent);
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Decrypted content written to ${outFile}.`)
      );
      expect(fs.readFileSync(outFile, "utf8")).toBe(originalContent); // Verify actual file content
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should exit with error if --secret is missing", async () => {
      await expect(
        program.parseAsync(["decrypt", "--data", "encrypted-test"], {
          from: "user",
        })
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining("Error: --secret is required for decryption.")
      );
    });

    it("should exit with error if no input source is provided", async () => {
      await expect(
        program.parseAsync(["decrypt", "--secret", secret], { from: "user" })
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining(
          "Error: One of --file or --data must be provided."
        )
      );
    });

    it("should exit with error if both --file and --data are provided", async () => {
      const fTxtPath = createTestFile("f.txt", "dummy content"); // Create the dummy file
      await expect(
        program.parseAsync(
          ["decrypt", "--file", fTxtPath, "--data", "d", "--secret", secret],
          { from: "user" }
        )
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining(
          "Error: Only one of --file or --data can be provided."
        )
      );
    });

    it("should exit with error on decryption failure", async () => {
      // We will simply check that an error is logged and the process exits.
      // We are no longer asserting a specific error message, as it was mock-dependent.
      await expect(
        program.parseAsync(
          [
            "decrypt",
            "--data",
            Buffer.from("invalid-hex-data").toString("hex"), // Provide invalid hex data to trigger real error
            "--secret",
            secret,
          ],
          { from: "user" }
        )
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalled();
    });
  });

  describe("obfuscate command", () => {
    const secret = "test-obfuscation-secret";

    it("should obfuscate a single file", async () => {
      const filePath = createTestFile("test.txt", "some content");
      await program.parseAsync(
        ["obfuscate", "--target", filePath, "--secret", secret],
        { from: "user" }
      );
      const obfuscatedFilePath = `${filePath}.enc`;
      expect(fs.readFileSync).toHaveBeenCalledWith(filePath); // Read original file
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        obfuscatedFilePath,
        expect.any(Buffer)
      ); // Write obfuscated content
      expect(fs.existsSync(filePath)).toBe(true); // Original should still exist
      expect(fs.existsSync(obfuscatedFilePath)).toBe(true);

      // Verify content by deobfuscating the written file
      const writtenBuffer = fs.readFileSync(obfuscatedFilePath);
      const deobfuscated = Obfuscation.deobfuscate(secret, writtenBuffer);
      expect(deobfuscated.toString()).toBe("some content");

      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(
          `Obfuscated ${filePath} to ${obfuscatedFilePath}`
        )
      );
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Successfully obfuscated 1 file(s).`)
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should obfuscate a single file and remove original", async () => {
      const filePath = createTestFile("test-remove.txt", "content to remove");
      await program.parseAsync(
        [
          "obfuscate",
          "--target",
          filePath,
          "--secret",
          secret,
          "--remove-original",
        ],
        { from: "user" }
      );
      const obfuscatedFilePath = `${filePath}.enc`;
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        obfuscatedFilePath,
        expect.any(Buffer)
      );
      expect(fs.unlinkSync).toHaveBeenCalledWith(filePath); // Original file removed
      expect(fs.existsSync(filePath)).toBe(false); // Original should not exist
      expect(fs.existsSync(obfuscatedFilePath)).toBe(true);

      // Verify content by deobfuscating the written file
      const writtenBuffer = fs.readFileSync(obfuscatedFilePath);
      const deobfuscated = Obfuscation.deobfuscate(secret, writtenBuffer);
      expect(deobfuscated.toString()).toBe("content to remove");

      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Removed original file: ${filePath}`)
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should obfuscate files in a directory", async () => {
      const testDir = createTestDir("my-dir");
      const file1 = createTestFile(path.join("my-dir", "file1.txt"), "c1");
      const file2 = createTestFile(path.join("my-dir", "file2.txt"), "c2");

      await program.parseAsync(
        ["obfuscate", "--target", testDir, "--secret", secret],
        { from: "user" }
      );

      const obfuscatedFile1 = `${file1}.enc`;
      const obfuscatedFile2 = `${file2}.enc`;

      expect(fs.writeFileSync).toHaveBeenCalledWith(
        obfuscatedFile1,
        expect.any(Buffer)
      );
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        obfuscatedFile2,
        expect.any(Buffer)
      );
      expect(fs.existsSync(file1)).toBe(true);
      expect(fs.existsSync(file2)).toBe(true);
      expect(fs.existsSync(obfuscatedFile1)).toBe(true);
      expect(fs.existsSync(obfuscatedFile2)).toBe(true);

      // Verify content by deobfuscating the written files
      const writtenBuffer1 = fs.readFileSync(obfuscatedFile1);
      const deobfuscated1 = Obfuscation.deobfuscate(secret, writtenBuffer1);
      expect(deobfuscated1.toString()).toBe("c1");
      const writtenBuffer2 = fs.readFileSync(obfuscatedFile2);
      const deobfuscated2 = Obfuscation.deobfuscate(secret, writtenBuffer2);
      expect(deobfuscated2.toString()).toBe("c2");

      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Obfuscated ${file1} to ${obfuscatedFile1}`)
      );
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Obfuscated ${file2} to ${obfuscatedFile2}`)
      );
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Successfully obfuscated 2 file(s).`)
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should obfuscate files in 'assets' directory under specified root", async () => {
      const projectRootRelative = "project-root";
      const libRelative = path.join(projectRootRelative, "lib");
      const assetsRelative = path.join(libRelative, "assets");
      const assetFileRelative = path.join(assetsRelative, "asset.json");

      // Create the absolute paths for directories
      const absoluteRootDir = createTestDir(projectRootRelative); // tempDir/project-root
      createTestDir(libRelative); // tempDir/project-root/lib
      createTestDir(assetsRelative); // tempDir/project-root/lib/assets

      // Create the test file using its path relative to tempDir
      const testFile = createTestFile(assetFileRelative, "asset data");

      await program.parseAsync(
        ["obfuscate", "--root", absoluteRootDir, "--secret", secret],
        { from: "user" }
      );

      const obfuscatedTestFile = `${testFile}.enc`;
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        obfuscatedTestFile,
        expect.any(Buffer)
      );
      expect(fs.existsSync(testFile)).toBe(true);
      expect(fs.existsSync(obfuscatedTestFile)).toBe(true);

      // Verify content by deobfuscating the written file
      const writtenBuffer = fs.readFileSync(obfuscatedTestFile);
      const deobfuscated = Obfuscation.deobfuscate(secret, writtenBuffer);
      expect(deobfuscated.toString()).toBe("asset data");

      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(
          `Obfuscated ${testFile} to ${obfuscatedTestFile}`
        )
      );
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Successfully obfuscated 1 file(s).`)
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should handle --remove-original-in correctly", async () => {
      createTestDir("dir1");
      const file1 = createTestFile(path.join("dir1", "file1.txt"), "content1");
      createTestDir("dir2");
      const file2 = createTestFile(path.join("dir2", "file2.txt"), "content2");

      await program.parseAsync(
        [
          "obfuscate",
          "--targets",
          `${file1},${file2}`,
          "--secret",
          secret,
          "--remove-original-in",
          "dir1", // Only remove originals in dir1
        ],
        { from: "user" }
      );

      // Verify obfuscated content by reading and deobfuscating files
      const obfuscatedFile1 = `${file1}.enc`;
      const obfuscatedFile2 = `${file2}.enc`;

      const deobfuscated1 = Obfuscation.deobfuscate(
        secret,
        fs.readFileSync(obfuscatedFile1)
      );
      expect(deobfuscated1.toString()).toBe("content1");

      const deobfuscated2 = Obfuscation.deobfuscate(
        secret,
        fs.readFileSync(obfuscatedFile2)
      );
      expect(deobfuscated2.toString()).toBe("content2");
    });

    it("should prioritize --keep-original over --remove-original", async () => {
      const filePath = createTestFile("test-keep.txt", "content to keep");
      await program.parseAsync(
        [
          "obfuscate",
          "--target",
          filePath,
          "--secret",
          secret,
          "--remove-original",
          "--keep-original",
        ],
        { from: "user" }
      );
      const obfuscatedFilePath = `${filePath}.enc`;
      expect(fs.existsSync(filePath)).toBe(true); // Original should still exist
      expect(fs.existsSync(obfuscatedFilePath)).toBe(true);
      expect(fs.unlinkSync).not.toHaveBeenCalledWith(filePath);

      // Verify content by deobfuscating the written file
      const writtenBuffer = fs.readFileSync(obfuscatedFilePath);
      const deobfuscated = Obfuscation.deobfuscate(secret, writtenBuffer);
      expect(deobfuscated.toString()).toBe("content to keep");
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should exit with error if --secret is missing", async () => {
      const filePath = createTestFile("temp.txt", "data");
      await expect(
        program.parseAsync(["obfuscate", "--target", filePath], {
          from: "user",
        })
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining("Error: --secret is required for obfuscation.")
      );
    });

    it("should exit with error if no valid targets are found", async () => {
      await expect(
        program.parseAsync(
          [
            "obfuscate",
            "--secret",
            secret,
            "--target",
            "non-existent-file.txt",
          ],
          { from: "user" }
        )
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining(
          "No valid target files or directories found for obfuscation."
        )
      );
    });
  });

  describe("deobfuscate command", () => {
    const secret = "test-obfuscation-secret";

    it("should deobfuscate a single file", async () => {
      const obfuscatedFilePath = createObfuscatedFile(
        "test.txt",
        "original content",
        secret
      );
      const originalFilePath = obfuscatedFilePath.replace(".enc", "");

      await program.parseAsync(
        ["deobfuscate", "--target", obfuscatedFilePath, "--secret", secret],
        { from: "user" }
      );

      expect(fs.readFileSync).toHaveBeenCalledWith(obfuscatedFilePath);
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        originalFilePath,
        Buffer.from("original content")
      );
      expect(fs.existsSync(obfuscatedFilePath)).toBe(true); // Encrypted should still exist
      expect(fs.existsSync(originalFilePath)).toBe(true); // Original should now exist
      expect(fs.readFileSync(originalFilePath).toString()).toBe(
        "original content"
      );
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(
          `Deobfuscated ${obfuscatedFilePath} to ${originalFilePath}`
        )
      );
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Successfully deobfuscated 1 file(s).`)
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should deobfuscate a single file and remove obfuscated original", async () => {
      const obfuscatedFilePath = createObfuscatedFile(
        "test-remove.txt",
        "content to remove",
        secret
      );
      const originalFilePath = obfuscatedFilePath.replace(".enc", "");

      await program.parseAsync(
        [
          "deobfuscate",
          "--target",
          obfuscatedFilePath,
          "--secret",
          secret,
          "--remove-original", // This means remove the .enc file
        ],
        { from: "user" }
      );

      expect(fs.unlinkSync).toHaveBeenCalledWith(obfuscatedFilePath); // .enc file removed
      expect(fs.existsSync(obfuscatedFilePath)).toBe(false); // .enc should not exist
      expect(fs.existsSync(originalFilePath)).toBe(true); // Original should exist
      expect(fs.readFileSync(originalFilePath).toString()).toBe(
        "content to remove"
      );
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Removed original file: ${obfuscatedFilePath}`)
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should deobfuscate files in a directory", async () => {
      createTestDir("my-dir-enc"); // Create the directory
      const file1Enc = createObfuscatedFile(
        path.join("my-dir-enc", "file1.txt"),
        "c1",
        secret
      );
      const file2Enc = createObfuscatedFile(
        path.join("my-dir-enc", "file2.txt"),
        "c2",
        secret
      );

      await program.parseAsync(
        [
          "deobfuscate",
          "--target",
          path.join(tempDir, "my-dir-enc"), // Pass the absolute path of the directory
          "--secret",
          secret,
        ],
        { from: "user" }
      );

      const file1 = file1Enc.replace(".enc", "");
      const file2 = file2Enc.replace(".enc", "");

      expect(fs.writeFileSync).toHaveBeenCalledWith(file1, Buffer.from(`c1`));
      expect(fs.writeFileSync).toHaveBeenCalledWith(file2, Buffer.from(`c2`));
      expect(fs.existsSync(file1Enc)).toBe(true);
      expect(fs.existsSync(file2Enc)).toBe(true);
      expect(fs.existsSync(file1)).toBe(true);
      expect(fs.existsSync(file2)).toBe(true);
      expect(fs.readFileSync(file1).toString()).toBe("c1");
      expect(fs.readFileSync(file2).toString()).toBe("c2");
      expect(mockLog).toHaveBeenCalledWith(
        expect.stringContaining(`Successfully deobfuscated 2 file(s).`)
      );
      expect(mockProcessExit).not.toHaveBeenCalled();
    });

    it("should handle --remove-original-in correctly during deobfuscation", async () => {
      createTestDir("dir1-enc");
      const file1Enc = createObfuscatedFile(
        path.join("dir1-enc", "file1.txt"),
        "content1",
        secret
      );
      createTestDir("dir2-enc");
      const file2Enc = createObfuscatedFile(
        path.join("dir2-enc", "file2.txt"),
        "content2",
        secret
      );

      await program.parseAsync(
        [
          "deobfuscate",
          "--targets",
          `${file1Enc},${file2Enc}`,
          "--secret",
          secret,
          "--remove-original-in",
          "dir1-enc", // Only remove .enc files in dir1-enc
        ],
        { from: "user" }
      );

      expect(fs.existsSync(file1Enc)).toBe(false); // Should be removed
      expect(fs.existsSync(file1Enc.replace(".enc", ""))).toBe(true);
      expect(fs.existsSync(file2Enc)).toBe(true); // Should not be removed
      expect(fs.existsSync(file2Enc.replace(".enc", ""))).toBe(true);
      expect(fs.readFileSync(file1Enc.replace(".enc", "")).toString()).toBe(
        "content1"
      );
      expect(fs.readFileSync(file2Enc.replace(".enc", "")).toString()).toBe(
        "content2"
      );

      expect(fs.unlinkSync).toHaveBeenCalledWith(file1Enc);
      expect(fs.unlinkSync).not.toHaveBeenCalledWith(file2Enc);
    });

    it("should exit with error if --secret is missing", async () => {
      const filePath = createObfuscatedFile("temp.txt", "data", secret);
      await expect(
        program.parseAsync(["deobfuscate", "--target", filePath], {
          from: "user",
        })
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining(
          "Error: --secret is required for deobfuscation."
        )
      );
    });

    it("should exit with error if no valid targets are found", async () => {
      await expect(
        program.parseAsync(
          [
            "deobfuscate",
            "--secret",
            secret,
            "--target",
            "non-existent-file.txt.enc",
          ],
          { from: "user" }
        )
      ).rejects.toThrow("process.exit: 1");
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining(
          "No valid target files or directories found for deobfuscation."
        )
      );
    });

    it("should exit with error on deobfuscation failure", async () => {
      // Write invalid (too short) data directly to a .enc file
      const badFilePath = path.join(tempDir, "bad.txt.enc");
      fs.writeFileSync(badFilePath, Buffer.from("short"));

      await expect(
        program.parseAsync(
          ["deobfuscate", "--target", badFilePath, "--secret", secret],
          { from: "user" }
        )
      ).rejects.toThrow("process.exit: 1");

      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining("Deobfuscation of")
      );
      expect(mockError).toHaveBeenCalledWith(
        expect.stringContaining("failed: Invalid prompt payload (too short)")
      );
    });
  });
});