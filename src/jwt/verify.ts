import { JwtOptions } from "./types";
import { jwtVerify } from "jose";

export async function verify<OBJ extends object = object>(
  token: string,
  option: JwtOptions
): Promise<OBJ> {
  const key = new TextEncoder().encode(option.secret);
  const { payload } = await jwtVerify(token, key, {
    algorithms: ["HS256"],
  });
  return payload as unknown as OBJ;
}
