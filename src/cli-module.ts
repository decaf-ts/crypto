import { Command } from "commander";
import { Logging } from "@decaf-ts/logging";
import fs from "fs";
import { getSubtle } from "./common/crypto";
import { encryptContent, getDerivedKey, decryptContent } from "./common/utils";

const logger = Logging.for("crypto-cli");

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

export default function createCliProgram() {
  const program = new Command();
  program.name("crypto");
  program.description(
    "Exposes several commands for cryptographic functionality."
  );
  program.addCommand(encryptCmd);
  program.addCommand(decryptCmd);
  return program;
}
