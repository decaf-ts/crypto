import { Logger } from "@decaf-ts/logging";
import fs from "fs";
import path from "path";
import { Obfuscation } from "./node/Obfuscation";

// Helper function to recursively walk a directory
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

// Helper function to find 'assets' directories
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

// Helper to determine if original should be removed
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

// Obfuscate/Deobfuscate a single file
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

// Main processing function for targets (files or directories)
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
