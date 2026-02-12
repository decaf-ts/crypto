import { Logger } from "@decaf-ts/logging";
import fs from "fs";
import path from "path";
import { Obfuscation } from "./node/Obfuscation";

/**
 * @description Recursively walks a directory and calls a visitor function for each file.
 * @summary This function synchronously reads the contents of a directory. For each entry, if it's a directory, it recursively calls itself. If it's a file, it calls the provided visitor function with the full path to the file.
 * @param {string} dir - The directory to walk.
 * @param {function(string): void} visitor - A function to call for each file found.
 * @function walk
 * @memberOf module:@decaf-ts/crypto
 */
export function walk(dir: string, visitor: (filePath: string) => void) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, visitor);
    } else if (entry.isFile()) {
      visitor(full);
    }
  }
}

/**
 * @description Finds all directories named 'assets' within a given root directory.
 * @summary This function performs a breadth-first search starting from the `rootDir`. It explores all subdirectories, skipping `node_modules`, and collects the paths of all directories named 'assets'.
 * @param {string} rootDir - The root directory to start the search from.
 * @returns {string[]} An array of absolute paths to the 'assets' directories found.
 * @function findAssetDirs
 * @memberOf module:@decaf-ts/crypto
 */
export function findAssetDirs(rootDir: string): string[] {
  const results = [];
  const stack = [rootDir];
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

/**
 * @description Determines whether an original file should be removed based on the provided flags and configuration.
 * @summary This function checks three conditions to decide if a file should be removed:
 * 1. If the `removeOriginalFlag` is true, it always returns true.
 * 2. If `removeOriginalIn` is not provided or is empty, it returns false.
 * 3. It checks if the normalized file path is included in any of the paths specified in the `removeOriginalIn` array.
 * @param {string} filePath - The path to the file to check.
 * @param {boolean} removeOriginalFlag - A flag that, if true, forces the removal of the original file.
 * @param {string[]} removeOriginalIn - An array of directory paths. If the file path is within any of these directories, it should be removed.
 * @returns {boolean} True if the original file should be removed, false otherwise.
 * @function shouldRemoveOriginalFile
 * @memberOf module:@decaf-ts/crypto
 */
export function shouldRemoveOriginalFile(
  filePath: string,
  removeOriginalFlag: boolean,
  removeOriginalIn: string[]
): boolean {
  if (removeOriginalFlag) return true;
  if (!removeOriginalIn || removeOriginalIn.length === 0) return false;
  const normalizedPath = filePath.replace(/\\/g, "/");
  return removeOriginalIn.some((needle) => normalizedPath.includes(needle));
}

/**
 * @description Obfuscates or deobfuscates a single file.
 * @summary This function reads a file, performs the specified operation (obfuscate or deobfuscate) on its content using the `Obfuscation` class, and writes the result to a new file. It also handles the removal of the original file based on the provided flags.
 * @param {string} filePath - The path to the file to process.
 * @param {string} secret - The secret to use for the operation.
 * @param {"obfuscate" | "deobfuscate"} operation - The operation to perform.
 * @param {boolean} removeOriginalFlag - A flag that, if true, forces the removal of the original file.
 * @param {string[]} removeOriginalIn - An array of directory paths. If the file path is within any of these directories, it should be removed.
 * @param {Logger} log - The logger instance to use for logging.
 * @returns {Promise<boolean>} A promise that resolves to true if the file was processed successfully, and false otherwise.
 * @function processSingleFile
 * @memberOf module:@decaf-ts/crypto
 * @mermaid
 * sequenceDiagram
 *   participant Client
 *   participant processSingleFile
 *   participant Obfuscation
 *   participant fs
 *
 *   Client->>processSingleFile: Call processSingleFile(filePath, secret, operation, ...)
 *   processSingleFile->>fs: readFileSync(filePath)
 *   fs-->>processSingleFile: fileBuffer
 *   alt operation is "obfuscate"
 *     processSingleFile->>Obfuscation: obfuscate(secret, fileBuffer)
 *     Obfuscation-->>processSingleFile: processedBuffer
 *   else operation is "deobfuscate"
 *     processSingleFile->>Obfuscation: deobfuscate(secret, fileBuffer)
 *     Obfuscation-->>processSingleFile: processedBuffer
 *   end
 *   processSingleFile->>fs: writeFileSync(newFilePath, processedBuffer)
 *   fs-->>processSingleFile:
 *   alt shouldRemoveOriginalFile is true
 *     processSingleFile->>fs: unlinkSync(filePath)
 *     fs-->>processSingleFile:
 *   end
 *   processSingleFile-->>Client: Returns true or false
 */
export async function processSingleFile(
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
    let processedBuffer;
    let newFilePath;

    if (isObfuscate) {
      processedBuffer = Obfuscation.obfuscate(secret, inputBuffer);
      newFilePath = `${filePath}${newExtension}`;
    } else {
      processedBuffer = Obfuscation.deobfuscate(secret, inputBuffer);
      newFilePath = filePath.slice(0, -expectedExtension.length); // Remove .enc extension
    }

    fs.writeFileSync(newFilePath, processedBuffer);
    log.info(
      `${isObfuscate ? "Obfuscated" : "Deobfuscated"} ${filePath} to ${newFilePath}`
    );

    if (
      shouldRemoveOriginalFile(filePath, removeOriginalFlag, removeOriginalIn)
    ) {
      fs.unlinkSync(filePath);
      log.info(`Removed original file: ${filePath}`);
    }
    return true;
  } catch (e: unknown) {
    log.error(
      `${isObfuscate ? "Obfuscation" : "Deobfuscation"} of ${filePath} failed: ${e}`
    );
    return false;
  }
}

/**
 * @description Processes a list of target files or directories, performing obfuscation or deobfuscation on them.
 * @summary This function iterates over a list of targets. If a target is a file, it calls `processSingleFile` on it. If it's a directory, it walks the directory and calls `processSingleFile` on each file found.
 * @param {string[]} targets - An array of file or directory paths to process.
 * @param {string} secret - The secret to use for the operation.
 * @param {"obfuscate" | "deobfuscate"} operation - The operation to perform.
 * @param {boolean} removeOriginalFlag - A flag that, if true, forces the removal of the original file.
 * @param {string[]} removeOriginalIn - An array of directory paths. If the file path is within any of these directories, it should be removed.
 * @param {Logger} log - The logger instance to use for logging.
 * @returns {Promise<number>} A promise that resolves to the number of files processed successfully.
 * @function processTargets
 * @memberOf module:@decaf-ts/crypto
 */
export async function processTargets(
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
      const success = await processSingleFile(
        target,
        secret,
        operation,
        removeOriginalFlag,
        removeOriginalIn,
        log
      );
      if (success) processedCount++;
    } else if (stats.isDirectory()) {
      const filesToProcess: string[] = [];
      walk(target, (filePath) => filesToProcess.push(filePath));
      for (const filePath of filesToProcess) {
        const success = await processSingleFile(
          filePath,
          secret,
          operation,
          removeOriginalFlag,
          removeOriginalIn,
          log
        );
        if (success) processedCount++;
      }
    }
  }
  return processedCount;
}
