import { model, Model, required } from "@decaf-ts/decorator-validation";
import { pk, table, Repository } from "@decaf-ts/core";
// @ts-expect-error paths
import { RamAdapter } from "@decaf-ts/core/ram";
import { encrypt } from "../../src/integration/decorators";
import { getSubtle } from "../../src/common/crypto";
import { uses } from "@decaf-ts/decoration";

// exactly 32 bytes for AES-256 raw key import
const SECRET = "integration-test-secret-32bytes!";
const ALGORITHM = { name: "AES-GCM", length: 256 };

@uses("ram")
@table("secret_notes")
@model()
class SecretNote extends Model {
  @pk()
  noteId!: number;

  @required()
  title!: string;

  @encrypt(SECRET, ALGORITHM)
  secret?: string;

  constructor(data?: Partial<SecretNote>) {
    super(data);
  }
}

describe("@encrypt integration with RamAdapter", () => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let adapter: RamAdapter;
  let repo: Repository<SecretNote, RamAdapter>;

  beforeAll(async () => {
    adapter = new RamAdapter({ UUID: "test" });
    repo = Repository.forModel(SecretNote);
  });

  it("should encrypt on create and decrypt on read", async () => {
    const note = new SecretNote({
      title: "my note",
      secret: "top-secret-value",
    });

    const created = await repo.create(note);

    // After create the value in the model is still the encrypted hex
    // (afterCreate does not call afterRead). Verify it's a hex string.
    expect(typeof created.secret).toBe("string");
    expect(created.secret).not.toBe("top-secret-value");
    expect(created.secret!.length).toBeGreaterThan(24); // IV (24 hex) + ciphertext

    // Read should decrypt back to original
    const fetched = await repo.read(created.noteId);
    expect(fetched.secret).toBe("top-secret-value");
  });

  it("should re-encrypt when value changes on update", async () => {
    const note = new SecretNote({
      title: "update test",
      secret: "original-secret",
    });

    const created = await repo.create(note);
    const encryptedOnCreate = created.secret;

    // Read to get decrypted model, then change the secret
    const fetched = await repo.read(created.noteId);
    expect(fetched.secret).toBe("original-secret");

    fetched.secret = "new-secret";
    const updated = await repo.update(fetched);

    // The encrypted value should differ from the original
    expect(updated.secret).not.toBe(encryptedOnCreate);
    expect(typeof updated.secret).toBe("string");
    expect(updated.secret!.length).toBeGreaterThan(24);

    // Read again to verify it decrypts to the new value
    const fetchedAgain = await repo.read(updated.noteId);
    expect(fetchedAgain.secret).toBe("new-secret");
  });

  it("should still produce valid ciphertext when data is unchanged on update", async () => {
    const note = new SecretNote({
      title: "unchanged test",
      secret: "same-value",
    });

    const created = await repo.create(note);

    // Read and update with the same secret value
    const fetched = await repo.read(created.noteId);
    expect(fetched.secret).toBe("same-value");

    // Set the same value and update
    fetched.secret = "same-value";
    const updated = await repo.update(fetched);

    // The value should be a valid encrypted hex string
    expect(typeof updated.secret).toBe("string");
    expect(updated.secret!.length).toBeGreaterThan(24);

    // Read still decrypts correctly
    const fetchedAgain = await repo.read(updated.noteId);
    expect(fetchedAgain.secret).toBe("same-value");
  });

  it("should handle undefined encrypted field on create and read", async () => {
    const note = new SecretNote({
      title: "no secret",
      // secret is undefined
    });

    const created = await repo.create(note);
    expect(created.secret).toBeUndefined();

    const fetched = await repo.read(created.noteId);
    expect(fetched.secret).toBeUndefined();
  });

  it("should encrypt when updating a previously undefined field", async () => {
    const note = new SecretNote({
      title: "add secret later",
    });

    const created = await repo.create(note);
    expect(created.secret).toBeUndefined();

    // Read, set a secret, then update
    const fetched = await repo.read(created.noteId);
    fetched.secret = "late-secret";
    const updated = await repo.update(fetched);

    expect(typeof updated.secret).toBe("string");
    expect(updated.secret).not.toBe("late-secret");

    const fetchedAgain = await repo.read(updated.noteId);
    expect(fetchedAgain.secret).toBe("late-secret");
  });

  it("should encrypt without comparison when mergeForUpdate is off", async () => {
    const note = new SecretNote({
      title: "no-merge test",
      secret: "some-secret",
    });

    const created = await repo.create(note);

    // Read to get decrypted model
    const fetched = await repo.read(created.noteId);
    expect(fetched.secret).toBe("some-secret");

    // Update with mergeForUpdate disabled.
    // The decorator skips its comparison branch when the flag is absent.
    fetched.secret = "some-secret";
    const updated = await repo
      .override({ mergeForUpdate: false } as any)
      .update(fetched);

    // Value should still be properly encrypted
    expect(typeof updated.secret).toBe("string");
    expect(updated.secret!.length).toBeGreaterThan(24);

    // Decryption should still work
    const fetchedAgain = await repo.read(updated.noteId);
    expect(fetchedAgain.secret).toBe("some-secret");
  });

  it("should produce valid ciphertext verifiable with SubtleCrypto", async () => {
    const note = new SecretNote({
      title: "verify crypto",
      secret: "verify-me",
    });

    const created = await repo.create(note);
    const hex = created.secret!;

    // Manually decrypt using SubtleCrypto to confirm format
    const subtle = await getSubtle();
    const keyMaterial = new TextEncoder().encode(SECRET);
    const cryptoKey = await subtle.importKey(
      "raw",
      keyMaterial,
      ALGORITHM,
      true,
      ["encrypt", "decrypt"]
    );

    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }

    const iv = bytes.slice(0, 12);
    const ciphertext = bytes.slice(12);

    const decrypted = await subtle.decrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      ciphertext
    );
    expect(JSON.parse(new TextDecoder().decode(decrypted))).toBe("verify-me");
  });
});
