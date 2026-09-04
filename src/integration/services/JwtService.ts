import { description } from "@decaf-ts/decoration";
import {
  ClientBasedService,
  MaybeContextualArg,
  PersistenceKeys,
} from "@decaf-ts/core";
import { sign } from "../../jwt/sign";
import {
  decodeJwtPayload,
  getTokenPayload as decodeTokenPayload,
  getUser as decodeJwtUser,
  verify,
  verifyJwt,
} from "../../jwt/verify";
import type { JwtOptions, JwtClaims } from "../../jwt/types";

export {
  decodeJwtPayload,
  decodeTokenPayload as getTokenPayload,
  decodeJwtUser as getUser,
};

const JWT_SECRET_ENV = "JWT__SECRET";
const JWT_EXPIRY_ENV = "JWT__EXPIRY";
const JWT_VERIFY_URL_ENV = "JWT__VERIFY_URL";
const JWT_CLOCK_TOLERANCE_SECONDS_ENV = "JWT__CLOCK_TOLERANCE_SECONDS";

function readJwtEnvConfig(): JwtOptions {
  const clockToleranceSeconds = process.env[JWT_CLOCK_TOLERANCE_SECONDS_ENV];
  const parsedClockToleranceSeconds = clockToleranceSeconds
    ? Number.parseInt(clockToleranceSeconds, 10)
    : undefined;
  return {
    secret: process.env[JWT_SECRET_ENV] || undefined,
    expiry: process.env[JWT_EXPIRY_ENV] || undefined,
    verifyUrl: process.env[JWT_VERIFY_URL_ENV] || undefined,
    clockToleranceSeconds:
      typeof parsedClockToleranceSeconds === "number" &&
      Number.isFinite(parsedClockToleranceSeconds)
        ? parsedClockToleranceSeconds
        : undefined,
  };
}

@description("Handles JWT operations")
export class JwtService extends ClientBasedService<void, JwtOptions> {
  constructor() {
    super();
  }

  async initialize(
    ...args: MaybeContextualArg<any>
  ): Promise<{ config: JwtOptions; client: void }> {
    const { log } = (
      await this.logCtx(args, PersistenceKeys.INITIALIZATION, true)
    ).for(this.initialize);
    const explicitConfig = (args[0] as JwtOptions | undefined) ?? {};
    const cfg: JwtOptions = {
      ...readJwtEnvConfig(),
      ...explicitConfig,
    };
    const mode = cfg.verifyUrl
      ? `verifyUrl=${cfg.verifyUrl}`
      : cfg.secret
        ? "local decode/HS256"
        : "decode-only";
    log.verbose(
      `Loaded jwt configuration (${mode}${cfg.expiry ? `, expiry=${cfg.expiry}` : ""})`
    );
    return {
      client: undefined,
      config: cfg,
    };
  }

  fromHeader(headers: { authorization?: string }) {
    const [type, token] = headers.authorization?.split(" ") ?? [];
    return type === "Bearer" ? token : undefined;
  }

  decodePayload<OBJ extends object = object>(jwt: string): OBJ | undefined {
    return decodeJwtPayload<OBJ>(jwt);
  }

  getTokenPayload<OBJ extends object = object>(jwt: string): OBJ | null {
    return decodeTokenPayload<OBJ>(jwt);
  }

  getUser(jwt: string): JwtClaims | undefined {
    return decodeJwtUser(jwt);
  }

  protected async createJwt(token: object) {
    return await sign(token, this.config);
  }

  async decodeJwt<OBJ extends object = object>(jwt: string): Promise<OBJ> {
    return verify<OBJ>(jwt, this.config);
  }

  async decodeAuthToken<OBJ extends object>(jwt: string): Promise<OBJ> {
    return verifyJwt(jwt, this.config);
  }

  async createAuthJwt<OBJ extends object>(obj: OBJ) {
    return {
      access_token: await this.createJwt(obj),
    };
  }
}
