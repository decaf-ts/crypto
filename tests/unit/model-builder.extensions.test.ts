import { Metadata } from "@decaf-ts/decoration";
import { ModelBuilder } from "@decaf-ts/decorator-validation";
import { CryptoKeys } from "../../src/integration/constants";
import "../../src/overrides/index";

describe("crypto ModelBuilder extensions", () => {
  it("marks properties as encrypted", () => {
    const builder = ModelBuilder.builder();
    builder.setName("CryptoBuilderModel");
    builder.string("ssn");
    builder.encrypt("ssn", "secret", { name: "AES-GCM" });

    const Dynamic = builder.build();

    expect(
      Metadata.get(Dynamic, Metadata.key(CryptoKeys.ENCRYPTED, "ssn"))
    ).toBeDefined();
  });
});
