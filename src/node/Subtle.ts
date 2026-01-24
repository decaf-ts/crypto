import { SubtleCrypto } from "../common/subtle";
import crypto from "crypto";

export const Subtle: SubtleCrypto = crypto.subtle as SubtleCrypto;
