import "@decaf-ts/decorator-validation";
import { Model, ModelBuilder } from "@decaf-ts/decorator-validation";
import { encrypt, SecretFunction } from "../integration/decorators";

declare module "@decaf-ts/decorator-validation" {
  export interface ModelBuilder<M> {
    encrypt<N extends keyof M>(
      attr: N,
      secret: string | SecretFunction,
      algorithm: Parameters<typeof encrypt>[1]
    ): ModelBuilder<M>;
    decorateClass(decorator: ClassDecorator): ModelBuilder<M>;
  }
}

const builderPrototype = ModelBuilder.prototype as ModelBuilder<any> & {
  encrypt: (
    attr: keyof any,
    secret: string | SecretFunction,
    algorithm: Parameters<typeof encrypt>[1]
  ) => ModelBuilder<any>;
};

if (!builderPrototype.decorateClass) {
  builderPrototype.decorateClass = function (decorator: ClassDecorator) {
    if (!(this as any)._classDecorators) {
      (this as any)._classDecorators = [];
    }
    (this as any)._classDecorators.push(decorator);
    return this;
  };
}

const ensureAttributeBuilder = <M extends Model, N extends keyof M>(
  builder: ModelBuilder<M>,
  attr: N
) => {
  const attributes = (builder as any).attributes as
    | Map<keyof M, any>
    | undefined;
  if (attributes?.has(attr)) return attributes.get(attr);
  return (builder as any).attribute(attr, Object);
};

const applyDecorator = <M extends Model, N extends keyof M>(
  builder: ModelBuilder<M>,
  attr: N,
  decorator: PropertyDecorator
) => {
  ensureAttributeBuilder(builder, attr).decorate(decorator);
  return builder;
};

builderPrototype.encrypt = function (
  attr: any,
  secret: string | SecretFunction,
  algorithm: Parameters<typeof encrypt>[1]
) {
  return applyDecorator(this, attr, encrypt(secret, algorithm));
};
