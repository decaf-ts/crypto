import { SignJWT } from "jose";
import { JwtOptions } from "./types";

export async function sign(obj: object, option: JwtOptions) {
  const key = new TextEncoder().encode(option.secret);
  // Add standard claims as needed (exp, iat, iss, aud, etc.)
  return await new SignJWT({ ...obj })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(option.expiry || "5m")
    .sign(key);
}
