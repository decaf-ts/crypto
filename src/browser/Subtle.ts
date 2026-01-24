import { SubtleCrypto } from "../common/subtle";

if (!(globalThis as any).window || !(globalThis as any).window.crypto || !(globalThis as any).window.crypto.subtle)
  throw new Error(`You don't seem to be in a browser environment capable to supporting subtle crypto`)

export const Subtle: SubtleCrypto = (globalThis as any).window.crypto.subtle as any;