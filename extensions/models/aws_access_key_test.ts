/**
 * Unit tests for aws_access_key.ts — preflight ordering (nothing is minted
 * when there is nowhere to put it), the two-key cap, delivery with read-back,
 * rollback on failed delivery, deactivate/delete guards, and secret hygiene,
 * against a fake IAM client and a fake vault. No live calls.
 * @module
 */
import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  _internal,
  createPreflight,
  fingerprint,
  type IamLike,
  model,
  slotCheck,
  type VaultLike,
} from "./aws_access_key.ts";

const SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const NEW_ID = "AKIAIOSFODNN7EXAMPLE";
const OLD_ID = "AKIAOLDKEY000000EXAM";

type Key = { id: string; status: "Active" | "Inactive" };

/** Fake IAM holding one user's keys; records every command it sees. */
function fakeIam(initial: Key[] = []) {
  const keys = [...initial];
  const calls: string[] = [];
  const iam: IamLike = {
    // deno-lint-ignore require-await
    send: async (command: unknown) => {
      const name = (command as object).constructor.name;
      const input = (command as { input: Record<string, unknown> }).input;
      calls.push(name);
      switch (name) {
        case "ListAccessKeysCommand":
          return {
            AccessKeyMetadata: keys.map((k) => ({
              AccessKeyId: k.id,
              Status: k.status,
              CreateDate: new Date("2026-01-01T00:00:00Z"),
            })),
            IsTruncated: false,
          };
        case "GetAccessKeyLastUsedCommand":
          return { AccessKeyLastUsed: { ServiceName: "N/A", Region: "N/A" } };
        case "CreateAccessKeyCommand":
          keys.push({ id: NEW_ID, status: "Active" });
          return {
            AccessKey: {
              AccessKeyId: NEW_ID,
              SecretAccessKey: SECRET,
              Status: "Active",
              CreateDate: new Date("2026-09-23T00:00:00Z"),
            },
          };
        case "UpdateAccessKeyCommand": {
          const k = keys.find((x) => x.id === input.AccessKeyId);
          if (k) k.status = input.Status as "Active" | "Inactive";
          return {};
        }
        case "DeleteAccessKeyCommand": {
          const i = keys.findIndex((x) => x.id === input.AccessKeyId);
          if (i >= 0) keys.splice(i, 1);
          return {};
        }
      }
      throw new Error(`unexpected command ${name}`);
    },
  };
  return { iam, keys, calls };
}

function fakeVault(opts: { failPut?: boolean; corruptRead?: boolean } = {}) {
  const store = new Map<string, string>();
  const vault: VaultLike = {
    getVaultNames: () => ["_internal", "secrets"],
    // deno-lint-ignore require-await
    put: async (v, k, value) => {
      if (opts.failPut) throw new Error("vault unavailable");
      store.set(`${v}:${k}`, value);
    },
    // deno-lint-ignore require-await
    get: async (v, k) => {
      const s = store.get(`${v}:${k}`) ?? "";
      return opts.corruptRead ? s + "x" : s;
    },
  };
  return { vault, store };
}

function ctx(
  vault: VaultLike | undefined,
  g: Record<string, unknown> = {},
) {
  const logs: string[] = [];
  const written: Array<{ spec: string; name: string; data: unknown }> = [];
  const redacted: string[] = [];
  // swamp rejects two outputs with one instance name in a single method
  // execution, across specs. Enforce it here; withIam() marks each execution.
  const seen = new Set<string>();
  currentSeen = seen;
  const log = (m: string, p?: Record<string, unknown>) =>
    logs.push(m + " " + JSON.stringify(p ?? {}));
  return {
    context: {
      globalArgs: {
        userName: "example-state",
        region: "us-east-1",
        targetVault: "secrets",
        targetItem: "example-state",
        ...g,
      },
      logger: { info: log, warn: log },
      // deno-lint-ignore require-await
      writeResource: async (spec: string, name: string, data: unknown) => {
        if (seen.has(name)) {
          throw new Error(`Duplicate data instance name '${name}'`);
        }
        seen.add(name);
        written.push({ spec, name, data: structuredClone(data) });
        return { name };
      },
      // deno-lint-ignore require-await
      readResource: async (name: string) => {
        const hit = written.filter((w) => w.spec === "key" && w.name === name)
          .at(-1);
        return (hit?.data as Record<string, unknown>) ?? null;
      },
      vaultService: vault,
      redactor: { addSecret: (s: string) => redacted.push(s) },
    },
    logs,
    written,
    redacted,
    seen,
  };
}

let currentSeen: Set<string> | undefined;

function withIam<T>(iam: IamLike, fn: () => Promise<T>): Promise<T> {
  currentSeen?.clear();
  const orig = _internal.iamClient;
  _internal.iamClient = () => iam;
  return fn().finally(() => {
    _internal.iamClient = orig;
  });
}

// deno-lint-ignore no-explicit-any
const create = model.methods.create.execute as any;
// deno-lint-ignore no-explicit-any
const del = model.methods.delete.execute as any;
// deno-lint-ignore no-explicit-any
const deactivate = model.methods.deactivate.execute as any;

// --- preflight ---------------------------------------------------------------

Deno.test("preflight: refuses without targetVault/targetItem", () => {
  const { vault } = fakeVault();
  assertThrows(
    () => createPreflight({ userName: "u", region: "us-east-1" }, vault),
    Error,
    "targetVault and targetItem",
  );
});

Deno.test("preflight: refuses an unknown vault and lists the real ones", () => {
  const { vault } = fakeVault();
  const err = assertThrows(() =>
    createPreflight(
      { userName: "u", region: "r", targetVault: "nope", targetItem: "i" },
      vault,
    )
  );
  assertStringIncludes((err as Error).message, "have: secrets");
  assert(!(err as Error).message.includes("_internal"));
});

Deno.test("create: mints NOTHING when the vault is missing", async () => {
  const { iam, calls } = fakeIam();
  const { context } = ctx(undefined);
  await assertRejects(
    () => withIam(iam, () => create({ allowSecond: false }, context)),
    Error,
    "Refusing to mint",
  );
  assertEquals(calls, []);
});

// --- slot cap ----------------------------------------------------------------

Deno.test("slotCheck: 0 ok, 1 needs allowSecond, 2 always refused", () => {
  slotCheck(0, false);
  assertThrows(() => slotCheck(1, false), Error, "allowSecond");
  slotCheck(1, true);
  assertThrows(() => slotCheck(2, true), Error, "AWS maximum");
});

Deno.test("create: refuses a second key without allowSecond, before minting", async () => {
  const { iam, calls } = fakeIam([{ id: OLD_ID, status: "Active" }]);
  const { vault } = fakeVault();
  const { context } = ctx(vault);
  await assertRejects(
    () => withIam(iam, () => create({ allowSecond: false }, context)),
    Error,
    "allowSecond",
  );
  assert(!calls.includes("CreateAccessKeyCommand"));
});

// --- happy path --------------------------------------------------------------

Deno.test("create: delivers both halves and verifies them", async () => {
  const { iam } = fakeIam();
  const { vault, store } = fakeVault();
  const { context, written, redacted } = ctx(vault);
  await withIam(iam, () => create({ allowSecond: false }, context));
  assertEquals(store.get("secrets:example-state/access-key-id"), NEW_ID);
  assertEquals(store.get("secrets:example-state/secret-access-key"), SECRET);
  assertEquals(redacted, [SECRET]);
  assertEquals(written.map((w) => w.name), [NEW_ID, "current", "summary"]);
  assertEquals(written[2].spec, "inventory");
  const r = written[0].data as Record<string, unknown>;
  assertEquals(r.secretFingerprint, await fingerprint(SECRET));
  assertEquals(r.deliveredTo, {
    vault: "secrets",
    accessKeyIdKey: "example-state/access-key-id",
    secretAccessKeyKey: "example-state/secret-access-key",
  });
});

Deno.test("create: the secret appears in no resource and no log line", async () => {
  const { iam } = fakeIam();
  const { vault } = fakeVault();
  const { context, written, logs } = ctx(vault);
  await withIam(iam, () => create({ allowSecond: false }, context));
  for (const w of written) {
    assert(!JSON.stringify(w.data).includes(SECRET), `leak in ${w.name}`);
  }
  for (const l of logs) assert(!l.includes(SECRET), `leak in log: ${l}`);
});

// --- rollback ----------------------------------------------------------------

Deno.test("create: a failed vault write deletes the new key", async () => {
  const { iam, keys, calls } = fakeIam();
  const { vault } = fakeVault({ failPut: true });
  const { context, written } = ctx(vault);
  await assertRejects(
    () => withIam(iam, () => create({ allowSecond: false }, context)),
    Error,
    "was deleted again",
  );
  assert(calls.includes("DeleteAccessKeyCommand"));
  assertEquals(keys, []);
  assertEquals(written, []);
});

Deno.test("create: a read-back mismatch deletes the new key", async () => {
  const { iam, keys } = fakeIam();
  const { vault } = fakeVault({ corruptRead: true });
  const { context } = ctx(vault);
  await assertRejects(
    () => withIam(iam, () => create({ allowSecond: false }, context)),
    Error,
    "read-back does not match",
  );
  assertEquals(keys, []);
});

// --- deactivate / delete -----------------------------------------------------

Deno.test("delete: refuses an Active key", async () => {
  const { iam, keys } = fakeIam([{ id: OLD_ID, status: "Active" }]);
  const { context } = ctx(undefined);
  await assertRejects(
    () => withIam(iam, () => del({ accessKeyId: OLD_ID }, context)),
    Error,
    "deactivate first",
  );
  assertEquals(keys.length, 1);
});

Deno.test("deactivate then delete removes the key", async () => {
  const { iam, keys } = fakeIam([{ id: OLD_ID, status: "Active" }]);
  const { context } = ctx(undefined);
  await withIam(iam, () => deactivate({ accessKeyId: OLD_ID }, context));
  assertEquals(keys[0].status, "Inactive");
  await withIam(iam, () => del({ accessKeyId: OLD_ID }, context));
  assertEquals(keys, []);
});

Deno.test("delete: an unknown key is a no-op, not an error", async () => {
  const { iam, calls } = fakeIam();
  const { context } = ctx(undefined);
  const out = await withIam(
    iam,
    () => del({ accessKeyId: OLD_ID }, context),
  ) as { dataHandles: unknown[] };
  assertEquals(out.dataHandles, []);
  assert(!calls.includes("DeleteAccessKeyCommand"));
});

// --- check -------------------------------------------------------------------

Deno.test("valid-target: vault and item travel together", () => {
  const check = model.checks["valid-target"].execute;
  assertEquals(check({ globalArgs: { userName: "u" } }).pass, true);
  assertEquals(
    check({ globalArgs: { targetVault: "v", targetItem: "i" } }).pass,
    true,
  );
  assertEquals(check({ globalArgs: { targetVault: "v" } }).pass, false);
  assertEquals(
    check({ globalArgs: { targetVault: "v", targetItem: "a/b" } }).pass,
    false,
  );
});

// --- record keeping ----------------------------------------------------------

Deno.test("deactivate keeps the delivery record create wrote", async () => {
  const { iam } = fakeIam();
  const { vault } = fakeVault();
  const { context, written } = ctx(vault);
  await withIam(iam, () => create({ allowSecond: false }, context));
  await withIam(iam, () => deactivate({ accessKeyId: NEW_ID }, context));
  const last = written.filter((w) => w.spec === "key" && w.name === NEW_ID)
    .at(-1)!.data as Record<string, unknown>;
  assertEquals(last.status, "Inactive");
  assertEquals(last.secretFingerprint, await fingerprint(SECRET));
  assert(last.deliveredTo !== null);
});

Deno.test("delete refreshes the inventory", async () => {
  const { iam } = fakeIam([{ id: OLD_ID, status: "Inactive" }]);
  const { context, written } = ctx(undefined);
  await withIam(iam, () => del({ accessKeyId: OLD_ID }, context));
  const inv = written.at(-1)!;
  assertEquals(inv.spec, "inventory");
  assertEquals((inv.data as Record<string, unknown>).keyCount, 0);
  assertEquals((inv.data as Record<string, unknown>).slotsFree, 2);
});
