import { InternalError } from "@decaf-ts/db-decorators";
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
    const cfg: JwtOptions = args[0];
    if (!cfg) throw new InternalError(`Missing configuration for JwtService`);
    const mode = cfg.verifyUrl ? `verifyUrl=${cfg.verifyUrl}` : "local decode/HS256";
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
