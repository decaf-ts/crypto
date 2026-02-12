/**
 * @description This is the executable for the crypto CLI.
 * @summary This script imports the `createCliProgram` function from the `cli-module` and executes it, parsing the command-line arguments.
 * @memberOf module:@decaf-ts/crypto
 */
import crypto from "../cli-module";

crypto().parse(process.argv);
