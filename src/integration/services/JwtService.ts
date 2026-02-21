import { InternalError } from "@decaf-ts/db-decorators";
import { description } from "@decaf-ts/decoration";
import {
  ClientBasedService,
  MaybeContextualArg,
  PersistenceKeys,
} from "@decaf-ts/core";
import { sign, verify } from "../../jwt/index";

export type JwtOptions = {
  secret: string;
  expiry: string;
};

@description("Handles JWt operations")
export class JwtService extends ClientBasedService<void, JwtOptions> {
  private static enc = new TextEncoder();

  constructor() {
    super();
  }

  async initialize(
    ...args: MaybeContextualArg<any>
  ): Promise<{ config: JwtOptions; client: void }> {
    const { log } = (
      await this.logCtx(args, PersistenceKeys.INITIALIZATION, true)
    ).for(this.initialize);
    const cfg = args[0];
    if (!cfg) throw new InternalError(`Missing configuration for JwtService`);
    log.verbose(`Loaded jwt secret. validity set to ${cfg.expiry}`);
    return {
      client: undefined,
      config: cfg,
    };
  }

  fromHeader(headers: { authorization?: string }) {
    const [type, token] = headers.authorization?.split(" ") ?? [];
    return type === "Bearer" ? token : undefined;
  }

  protected async createJwt(token: object) {
    return await sign(token, this.config);
  }

  async decodeJwt<OBJ extends object = object>(jwt: string): Promise<OBJ> {
    return verify<OBJ>(jwt, this.config);
  }

  async decodeAuthToken<OBJ extends object>(jwt: string): Promise<OBJ> {
    return verify(jwt, this.config);
  }

  async createAuthJwt<OBJ extends object>(obj: OBJ) {
    return {
      access_token: await this.createJwt(obj),
    };
  }
}
