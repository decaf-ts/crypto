import { Command } from "commander";
import { Logging, Logger } from "@decaf-ts/logging";
import fs from "fs";
import path from "path";
import { encryptContent, getDerivedKey, decryptContent } from "./common/utils";
import { getSubtle } from "./common/crypto";
import { Obfuscation } from "./node/Obfuscation"; // Import Obfuscation class

const logger = Logging.for("crypto-cli");

// Helper function to recursively walk a directory
function walk(dir: string, visitor: (filePath: string) => void) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, visitor);
    } else if (entry.isFile()) {
      visitor(full);
    }
  }
}

// Helper function to find 'assets' directories
function findAssetDirs(rootDir: string): string[] {
  const results: string[] = [];
  const stack: string[] = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;

    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue; // Skip if directory cannot be read
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === "node_modules") continue; // Skip node_modules
      const full = path.join(current, entry.name);
      if (entry.name === "assets") {
        results.push(full);
        continue;
      }
      stack.push(full);
    }
  }
  return results;
}

// Helper to determine if original should be removed
function shouldRemoveOriginalFile(
  filePath: string,
  removeOriginalFlag: boolean,
  removeOriginalIn: string[]
): boolean {
  if (removeOriginalFlag) return true;
  if (!removeOriginalIn || removeOriginalIn.length === 0) return false;
  const normalizedPath = filePath.replace(/\\/g, "/");
  return removeOriginalIn.some((needle) => normalizedPath.includes(needle));
}

// Obfuscate/Deobfuscate a single file
async function processSingleFile(
  filePath: string,
  secret: string,
  operation: "obfuscate" | "deobfuscate",
  removeOriginalFlag: boolean,
  removeOriginalIn: string[],
  log: Logger
): Promise<boolean> {
  const isObfuscate = operation === "obfuscate";
  const expectedExtension = isObfuscate ? "" : ".enc";
  const newExtension = isObfuscate ? ".enc" : "";

  // Skip already processed files (e.g., .enc during obfuscation)
  if (isObfuscate && filePath.endsWith(".enc")) {
    log.debug(`Skipping already obfuscated file: ${filePath}`);
    return false;
  }
  // For deobfuscation, we expect .enc files. If not, skip and warn.
  if (!isObfuscate && !filePath.endsWith(".enc")) {
    log.warn(`Skipping non-.enc file during deobfuscation: ${filePath}`);
    return false;
  }

  try {
    const inputBuffer = fs.readFileSync(filePath);
    let processedBuffer: Buffer;
    let newFilePath: string;

    if (isObfuscate) {
      processedBuffer = Obfuscation.obfuscate(secret, inputBuffer);
      newFilePath = `${filePath}${newExtension}`;
    } else {
      processedBuffer = Obfuscation.deobfuscate(secret, inputBuffer);
      newFilePath = filePath.slice(0, -expectedExtension.length); // Remove .enc extension
    }

    fs.writeFileSync(newFilePath, processedBuffer);
    log.info(
      `${isObfuscate ? "Obfuscated" : "Deobfuscated"} ${filePath} to ${newFilePath}.`
    );

    if (
      shouldRemoveOriginalFile(filePath, removeOriginalFlag, removeOriginalIn)
    ) {
      fs.unlinkSync(filePath);
      log.info(`Removed original file: ${filePath}`);
    }
    return true;
  } catch (e: any) {
    log.error(
      `${isObfuscate ? "Obfuscation" : "Deobfuscation"} of ${filePath} failed: ${e.message}`
    );
    throw e; // Re-throw the error
  }
}

// Main processing function for targets (files or directories)
async function processTargets(
  targets: string[],
  secret: string,
  operation: "obfuscate" | "deobfuscate",
  removeOriginalFlag: boolean,
  removeOriginalIn: string[],
  log: Logger
): Promise<number> {
  let processedCount = 0;
  for (const target of targets) {
    if (!fs.existsSync(target)) {
      log.warn(`Target not found, skipping: ${target}`);
      continue;
    }

    const stats = fs.statSync(target);
    if (stats.isFile()) {
      await processSingleFile(
        // Await here to propagate error
        target,
        secret,
        operation,
        removeOriginalFlag,
        removeOriginalIn,
        log
      );
      processedCount++;
    } else if (stats.isDirectory()) {
      const filesToProcess: string[] = [];
      walk(target, (filePath) => filesToProcess.push(filePath));
      for (const filePath of filesToProcess) {
        await processSingleFile(
          // Await here to propagate error
          filePath,
          secret,
          operation,
          removeOriginalFlag,
          removeOriginalIn,
          log
        );
        processedCount++;
      }
    }
  }
  return processedCount;
}

const encryptCmd = new Command("encrypt")
  .option("-f, --file <string>", "Encrypt the content of a file.")
  .option("-d, --data <string>", "Encrypt the provided string data.")
  .option(
    "-o, --out <string>",
    "Output path. If not provided, prints to console for --data, or encrypts in place for --file."
  )
  .option("-s, --secret <string>", "REQUIRED: The encryption secret.")
  .option(
    "-a, --alg <string>",
    "The encryption algorithm name (e.g., AES-GCM).",
    "AES-GCM"
  )
  .option(
    "-l, --key-length <number>",
    "The key length in bits (e.g., 256 for AES-GCM).",
    "256"
  )
  .description("Encrypts data or file content.")
  .action(async (options: any) => {
    const log = logger.for("encrypt-command");
    const { file, data, out, secret, alg, keyLength } = options;

    if (!secret) {
      log.error("Error: --secret is required for encryption.");
      process.exit(1);
    }

    const inputCount = [file, data].filter(Boolean).length;
    if (inputCount === 0) {
      log.error("Error: One of --file or --data must be provided.");
      process.exit(1);
    }
    if (inputCount > 1) {
      log.error("Error: Only one of --file or --data can be provided.");
      process.exit(1);
    }

    let contentToProcess: string;
    let outputPath: string | undefined;

    if (file) {
      contentToProcess = fs.readFileSync(file, "utf-8");
      outputPath = out || file; // Default to in-place for files
    } else {
      // data
      contentToProcess = data;
      outputPath = out; // For data, 'out' is explicit, otherwise console
    }

    try {
      const subtle = await getSubtle();
      const encryptionKey = await getDerivedKey(
        subtle,
        secret,
        alg,
        parseInt(keyLength, 10),
        ["encrypt", "decrypt"]
      );
      const encryptedHex = await encryptContent(
        subtle,
        encryptionKey,
        alg,
        contentToProcess
      );

      if (outputPath) {
        fs.writeFileSync(outputPath, encryptedHex);
        log.info(`Encrypted content written to ${outputPath}.`);
      } else {
        console.log(encryptedHex);
      }
    } catch (e: any) {
      log.error(`Encryption failed: ${e.message}`);
      process.exit(1);
    }
  });

const decryptCmd = new Command("decrypt")
  .option("-f, --file <string>", "Decrypt the content of a file.")
  .option("-d, --data <string>", "Decrypt the provided hex string data.")
  .option(
    "-o, --out <string>",
    "Output path. If not provided, prints to console for --data, or decrypts in place for --file."
  )
  .option("-s, --secret <string>", "REQUIRED: The decryption secret.")
  .option(
    "-a, --alg <string>",
    "The decryption algorithm name (e.g., AES-GCM).",
    "AES-GCM"
  )
  .option(
    "-l, --key-length <number>",
    "The key length in bits (e.g., 256 for AES-GCM).",
    "256"
  )
  .description("Decrypts data or file content.")
  .action(async (options: any) => {
    const log = logger.for("decrypt-command");
    const { file, data, out, secret, alg, keyLength } = options;

    if (!secret) {
      log.error("Error: --secret is required for decryption.");
      process.exit(1);
    }

    const inputCount = [file, data].filter(Boolean).length;
    if (inputCount === 0) {
      log.error("Error: One of --file or --data must be provided.");
      process.exit(1);
    }
    if (inputCount > 1) {
      log.error("Error: Only one of --file or --data can be provided.");
      process.exit(1);
    }

    let contentToProcessHex: string;
    let outputPath: string | undefined;

    if (file) {
      contentToProcessHex = fs.readFileSync(file, "utf-8");
      outputPath = out || file; // Default to in-place for files
    } else {
      // data
      contentToProcessHex = data;
      outputPath = out; // For data, 'out' is explicit, otherwise console
    }

    try {
      const subtle = await getSubtle();
      const decryptionKey = await getDerivedKey(
        subtle,
        secret,
        alg,
        parseInt(keyLength, 10),
        ["encrypt", "decrypt"]
      );
      const decryptedContent = await decryptContent(
        subtle,
        decryptionKey,
        alg,
        contentToProcessHex
      );

      if (outputPath) {
        fs.writeFileSync(outputPath, decryptedContent);
        log.info(`Decrypted content written to ${outputPath}.`);
      } else {
        console.log(decryptedContent);
      }
    } catch (e: any) {
      log.error(`Decryption failed: ${e.message}`);
      process.exit(1);
    }
  });

const obfuscateCmd = new Command("obfuscate")
  .option("-s, --secret <string>", "REQUIRED: The encryption secret.")
  .option(
    "-r, --root <string>",
    "Root directory to search for 'assets' folders if no specific targets are provided. Defaults to current working directory.",
    process.cwd()
  )
  .option(
    "-t, --target <string>",
    "A specific file or directory to obfuscate. Can be used multiple times."
  )
  .option(
    "-T, --targets <string>",
    "Comma-separated list of files or directories to obfuscate."
  )
  .option(
    "--remove-original",
    "Deletes original files after obfuscation. Defaults to false.",
    false
  )
  .option(
    "--remove-original-in <string>",
    "Comma-separated list of directory names. Original files within these directories will be removed after obfuscation. Applies only if '--remove-original' is not set to true."
  )
  .option(
    "--keep-original",
    "Keeps original files, overriding '--remove-original' and '--remove-original-in'. Defaults to false.",
    false
  )
  .description("Obfuscates files or directories containing assets.")
  .action(async (options) => {
    const log = logger.for("obfuscate-command");
    const {
      secret,
      root,
      target,
      targets,
      removeOriginal,
      removeOriginalIn,
      keepOriginal,
    } = options;

    if (!secret) {
      log.error("Error: --secret is required for obfuscation.");
      process.exit(1);
    }

    let effectiveRemoveOriginal = removeOriginal;
    if (keepOriginal) {
      effectiveRemoveOriginal = false;
    }

    const removeOriginalInArray = removeOriginalIn
      ? removeOriginalIn.split(",")
      : [];

    const resolvedTargets: string[] = [];
    if (target) {
      resolvedTargets.push(target);
    }
    if (targets) {
      resolvedTargets.push(...targets.split(","));
    }

    if (resolvedTargets.length === 0) {
      // Replicate `obfuscate-prompts.cjs` logic to find asset dirs
      const searchRoots = [
        path.join(root, "lib"),
        path.join(root, "dist"),
        path.join(root, "src"),
      ].filter((p) => fs.existsSync(p));
      for (const searchRoot of searchRoots) {
        resolvedTargets.push(...findAssetDirs(searchRoot));
      }
    }

    const existingTargets = Array.from(
      new Set(resolvedTargets.filter((t) => fs.existsSync(t)))
    );

    if (existingTargets.length === 0) {
      log.error(
        `No valid target files or directories found for obfuscation. Searched in: ${resolvedTargets.join(", ")}`
      );
      process.exit(1);
    }

    log.info(`Obfuscating files under: ${existingTargets.join(", ")}`);
    const processedCount = await processTargets(
      existingTargets,
      secret,
      "obfuscate",
      effectiveRemoveOriginal,
      removeOriginalInArray,
      log
    );
    log.info(`Successfully obfuscated ${processedCount} file(s).`);
  });

const deobfuscateCmd = new Command("deobfuscate")
  .option("-s, --secret <string>", "REQUIRED: The decryption secret.")
  .option(
    "-r, --root <string>",
    "Root directory to search for 'assets' folders if no specific targets are provided. Defaults to current working directory.",
    process.cwd()
  )
  .option(
    "-t, --target <string>",
    "A specific file or directory to deobfuscate. Can be used multiple times."
  )
  .option(
    "-T, --targets <string>",
    "Comma-separated list of files or directories to deobfuscate."
  )
  .option(
    "--remove-original",
    "Deletes original .enc files after deobfuscation. Defaults to false.",
    false
  )
  .option(
    "--remove-original-in <string>",
    "Comma-separated list of directory names. Original .enc files within these directories will be removed after deobfuscation. Applies only if '--remove-original' is not set to true."
  )
  .option(
    "--keep-original",
    "Keeps original .enc files, overriding '--remove-original' and '--remove-original-in'. Defaults to false.",
    false
  )
  .description(
    "Deobfuscates files or directories that were previously obfuscated."
  )
  .action(async (options) => {
    const log = logger.for("deobfuscate-command");
    const {
      secret,
      root,
      target,
      targets,
      removeOriginal,
      removeOriginalIn,
      keepOriginal,
    } = options;

    if (!secret) {
      log.error("Error: --secret is required for deobfuscation.");
      process.exit(1);
    }

    let effectiveRemoveOriginal = removeOriginal;
    if (keepOriginal) {
      effectiveRemoveOriginal = false;
    }

    const removeOriginalInArray = removeOriginalIn
      ? removeOriginalIn.split(",")
      : [];

    const resolvedTargets: string[] = [];
    if (target) {
      resolvedTargets.push(target);
    }
    if (targets) {
      resolvedTargets.push(...targets.split(","));
    }

    if (resolvedTargets.length === 0) {
      // Replicate `obfuscate-prompts.cjs` logic to find asset dirs,
      // but here we expect .enc files within them
      const searchRoots = [
        path.join(root, "lib"),
        path.join(root, "dist"),
        path.join(root, "src"),
      ].filter((p) => fs.existsSync(p));
      for (const searchRoot of searchRoots) {
        resolvedTargets.push(...findAssetDirs(searchRoot));
      }
    }

    const existingTargets = Array.from(
      new Set(resolvedTargets.filter((t) => fs.existsSync(t)))
    );

    if (existingTargets.length === 0) {
      log.error(
        `No valid target files or directories found for deobfuscation. Searched in: ${resolvedTargets.join(", ")}`
      );
      process.exit(1);
    }

    log.info(`Deobfuscating files under: ${existingTargets.join(", ")}`);
    const processedCount = await processTargets(
      existingTargets,
      secret,
      "deobfuscate",
      effectiveRemoveOriginal,
      removeOriginalInArray,
      log
    );
    log.info(`Successfully deobfuscated ${processedCount} file(s).`);
  });

export default function createCliProgram() {
  const program = new Command();
  program.name("crypto");
  program.description(
    "Exposes several commands for cryptographic functionality."
  );
  program.addCommand(encryptCmd);
  program.addCommand(decryptCmd);
  program.addCommand(obfuscateCmd);
  program.addCommand(deobfuscateCmd);
  return program;
}
