/**
 * AWS IAM access key lifecycle — mint, inventory, deactivate and delete the
 * long-lived keys an IAM user authenticates with, and deliver a new key
 * straight into a swamp vault.
 *
 * `@swamp/aws/iam` manages the user and its policies, but has no access key
 * type: CloudFormation's `AWS::IAM::AccessKey` returns the secret only as a
 * `GetAtt` on stack creation, so Cloud Control cannot model it. That left the
 * one step that produces a secret as the one step done by hand. This model is
 * that step.
 *
 * Four things worth reading before use:
 *
 * 1. **The secret is disclosed exactly once**, by `CreateAccessKey`. No read
 *    path returns it. So `create` writes it into the configured vault *before*
 *    returning, reads it back to prove the write landed, and deletes the new
 *    key again if either step fails. A key whose secret was lost is worse than
 *    no key: it occupies one of the user's two slots and nobody can use it.
 *
 * 2. **Delivery is to a named vault item, not a swamp-generated key.** A
 *    sensitive resource field would vault the secret too, but under a key swamp
 *    derives from the model id, method and field path, in whichever vault is
 *    the repo default. Consumers outside swamp (a shell script's
 *    `op read op://vault/item/field`, a CI secret) need a stable, human-chosen
 *    address. `targetVault` + `targetItem` give it one:
 *    `<targetItem>/access-key-id` and `<targetItem>/secret-access-key`. This
 *    uses the method context's vault service directly, because a sensitive
 *    field's vault and key are fixed in the schema and cannot vary per
 *    instance.
 *
 * 3. **AWS allows two keys per user.** `create` refuses when the user already
 *    has one unless `allowSecond` is set — a second key is how a rotation
 *    overlaps, but an accidental second key is how a leaked first one survives
 *    a "rotation". It always refuses at two, before calling AWS.
 *
 * 4. **Nothing written by this model carries the secret.** The `key` resource
 *    holds the id, status, dates, last use, and a 12-hex SHA-256 fingerprint of
 *    each half, so a rotation can be verified against the vault without either
 *    value being printed. The secret is also registered with swamp's redactor
 *    the moment it exists.
 *
 * Credentials come from the AWS SDK default chain (env, profile,
 * `credential_process`, instance role). Creating and deleting keys needs
 * `iam:CreateAccessKey`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`,
 * `iam:UpdateAccessKey` and `iam:DeleteAccessKey` on the target user — a
 * principal that can mint keys for a user can become that user, so it should
 * not be the same principal your automation runs as day to day.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  CreateAccessKeyCommand,
  DeleteAccessKeyCommand,
  GetAccessKeyLastUsedCommand,
  IAMClient,
  ListAccessKeysCommand,
  UpdateAccessKeyCommand,
} from "npm:@aws-sdk/client-iam@3.1127.0";

// --- Constants ---------------------------------------------------------------

/** AWS hard limit on access keys per IAM user. */
export const MAX_KEYS_PER_USER = 2;

/** Field names written under `targetItem`. Match the common 1Password layout. */
export const ACCESS_KEY_ID_FIELD = "access-key-id";
/** Field under `targetItem` that receives the secret access key. */
export const SECRET_ACCESS_KEY_FIELD = "secret-access-key";

/** IAM is a global service; the SDK still wants a region for signing. */
export const DEFAULT_REGION = "us-east-1";

const IAM_USER_NAME_RE = /^[\w+=,.@-]{1,64}$/;
const ACCESS_KEY_ID_RE = /^[A-Z0-9]{16,128}$/;
// Vault item paths are interpolated into a vault key, and some vault backends
// shell out (the 1Password CLI does). Keep them to a boring character set.
const VAULT_ITEM_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

// --- Schemas -----------------------------------------------------------------

/** Per-instance configuration: which user, and where `create` delivers. */
export const GlobalArgsSchema = z.object({
  userName: z.string().regex(
    IAM_USER_NAME_RE,
    "IAM user names are 1-64 chars of letters, digits and +=,.@_-",
  ).describe("The IAM user whose access keys this instance manages."),
  region: z.string().regex(/^[a-z0-9-]+$/).default(DEFAULT_REGION).describe(
    "Region the IAM client signs for. IAM is global; leave the default unless your partition needs otherwise.",
  ),
  targetVault: z.string().min(1).optional().describe(
    "Name of the swamp vault `create` writes the new key into. Required by create; list/deactivate/delete do not use it.",
  ),
  targetItem: z.string().regex(
    VAULT_ITEM_RE,
    "Item names are 1-128 chars of letters, digits and ._- (no slashes, no op:// URIs)",
  ).optional().describe(
    "Item within targetVault. create writes <targetItem>/access-key-id and <targetItem>/secret-access-key.",
  ),
});
/** Parsed global arguments. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;
type RawGlobalArgs = Partial<Record<keyof GlobalArgs, unknown>>;

/** Arguments to `create`. */
export const CreateArgsSchema = z.object({
  allowSecond: z.boolean().default(false).describe(
    "Permit minting while the user already holds one key — the overlap step of a rotation. Off by default so an accidental second key cannot outlive the first.",
  ),
});

/** Arguments to `deactivate` and `delete`: the one key to act on. */
export const KeyIdArgsSchema = z.object({
  accessKeyId: z.string().regex(ACCESS_KEY_ID_RE).describe(
    "The access key id to act on (AKIA…).",
  ),
});

/** One access key's metadata. Never the secret. */
export const KeySchema = z.object({
  userName: z.string(),
  accessKeyId: z.string().describe("Access key id (AKIA…). Not a secret."),
  status: z.enum(["Active", "Inactive"]).nullable(),
  createdAt: z.string().nullable(),
  ageDays: z.number().nullable(),
  lastUsedAt: z.string().nullable(),
  lastUsedService: z.string().nullable(),
  lastUsedRegion: z.string().nullable(),
  accessKeyIdFingerprint: z.string().describe(
    "First 12 hex of SHA-256 over the access key id.",
  ),
  secretFingerprint: z.string().nullable().describe(
    "First 12 hex of SHA-256 over the secret; only known to the create run that minted it.",
  ),
  deliveredTo: z.object({
    vault: z.string(),
    accessKeyIdKey: z.string(),
    secretAccessKeyKey: z.string(),
  }).nullable().describe(
    "Where create wrote the key. Vault addresses only, never a value.",
  ),
  observedAt: z.string(),
});
/** A `key` resource as written. */
export type KeyResource = z.infer<typeof KeySchema>;

/** Every key the user holds, as of one list call. */
export const InventorySchema = z.object({
  userName: z.string(),
  keyCount: z.number(),
  activeCount: z.number(),
  slotsFree: z.number(),
  accessKeyIds: z.array(z.string()),
  observedAt: z.string(),
});

// --- Types -------------------------------------------------------------------

type Logger = {
  info: (message: string, props?: Record<string, unknown>) => void;
  warn: (message: string, props?: Record<string, unknown>) => void;
};

/** The slice of swamp's vault service this model uses. */
export type VaultLike = {
  getVaultNames: () => string[];
  put: (vaultName: string, key: string, value: string) => Promise<void>;
  get: (vaultName: string, key: string) => Promise<string>;
};

type ExecuteContext = {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
  readResource?: (
    instanceName: string,
  ) => Promise<Record<string, unknown> | null>;
  vaultService?: VaultLike;
  redactor?: { addSecret: (value: string) => void };
};

/** The IAM calls this model makes. Narrow so tests can fake it. */
export type IamLike = {
  send: (command: unknown) => Promise<Record<string, unknown>>;
};

// --- Helpers -----------------------------------------------------------------

/** First 12 hex chars of SHA-256 — enough to compare, useless to an attacker. */
export async function fingerprint(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 12);
}

/** Whole days from an ISO timestamp to `now`; null if absent or unparseable. */
export function daysSince(iso: string | null, now: Date): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((now.getTime() - t) / 86_400_000);
}

function isoOrNull(v: unknown): string | null {
  if (v instanceof Date) return v.toISOString();
  if (typeof v === "string" && v) return v;
  return null;
}

/** Vault keys for the two halves of a key under `targetItem`. */
export function vaultKeys(item: string): {
  accessKeyIdKey: string;
  secretAccessKeyKey: string;
} {
  return {
    accessKeyIdKey: `${item}/${ACCESS_KEY_ID_FIELD}`,
    secretAccessKeyKey: `${item}/${SECRET_ACCESS_KEY_FIELD}`,
  };
}

function errorName(err: unknown): string {
  return (err as { name?: string })?.name ?? "";
}

type ListedKey = {
  accessKeyId: string;
  status: "Active" | "Inactive" | null;
  createdAt: string | null;
};

async function listKeys(iam: IamLike, userName: string): Promise<ListedKey[]> {
  const out: ListedKey[] = [];
  let marker: string | undefined;
  do {
    const res = await iam.send(
      new ListAccessKeysCommand({ UserName: userName, Marker: marker }),
    );
    const items = (res.AccessKeyMetadata ?? []) as Array<
      Record<string, unknown>
    >;
    for (const k of items) {
      out.push({
        accessKeyId: String(k.AccessKeyId),
        status: (k.Status as "Active" | "Inactive") ?? null,
        createdAt: isoOrNull(k.CreateDate),
      });
    }
    marker = res.IsTruncated ? (res.Marker as string) : undefined;
  } while (marker);
  return out;
}

async function lastUsed(
  iam: IamLike,
  accessKeyId: string,
): Promise<
  { at: string | null; service: string | null; region: string | null }
> {
  const res = await iam.send(
    new GetAccessKeyLastUsedCommand({ AccessKeyId: accessKeyId }),
  );
  const lu = (res.AccessKeyLastUsed ?? {}) as Record<string, unknown>;
  // AWS reports "N/A" for a key that has never been used.
  const clean = (v: unknown) =>
    typeof v === "string" && v && v !== "N/A" ? v : null;
  return {
    at: isoOrNull(lu.LastUsedDate),
    service: clean(lu.ServiceName),
    region: clean(lu.Region),
  };
}

async function toKeyResource(
  iam: IamLike,
  userName: string,
  k: ListedKey,
  now: Date,
): Promise<KeyResource> {
  const lu = await lastUsed(iam, k.accessKeyId);
  return {
    userName,
    accessKeyId: k.accessKeyId,
    status: k.status,
    createdAt: k.createdAt,
    ageDays: daysSince(k.createdAt, now),
    lastUsedAt: lu.at,
    lastUsedService: lu.service,
    lastUsedRegion: lu.region,
    accessKeyIdFingerprint: await fingerprint(k.accessKeyId),
    secretFingerprint: null,
    deliveredTo: null,
    observedAt: now.toISOString(),
  };
}

/**
 * Everything `create` can check without calling AWS. Run before the key is
 * minted, because every failure after that point has to be undone.
 */
export function createPreflight(
  g: GlobalArgs,
  vault: VaultLike | undefined,
): { vaultName: string; item: string } {
  if (!g.targetVault || !g.targetItem) {
    throw new Error(
      "create needs both globalArguments.targetVault and targetItem — the " +
        "secret is disclosed once and must have somewhere to go before it is " +
        "minted.",
    );
  }
  if (!vault) {
    throw new Error(
      "No vault service is available to this method run, so the new secret " +
        "could not be stored. Refusing to mint a key that would be lost.",
    );
  }
  const names = vault.getVaultNames();
  if (!names.includes(g.targetVault)) {
    throw new Error(
      `targetVault "${g.targetVault}" is not a vault in this repo ` +
        `(have: ${
          names.filter((n) => !n.startsWith("_")).join(", ") || "none"
        }).`,
    );
  }
  if (g.targetVault.startsWith("_")) {
    throw new Error(`targetVault "${g.targetVault}" is reserved for swamp.`);
  }
  return { vaultName: g.targetVault, item: g.targetItem };
}

/** Refuse at the AWS cap, and at one key unless the caller asked for overlap. */
export function slotCheck(existing: number, allowSecond: boolean): void {
  if (existing >= MAX_KEYS_PER_USER) {
    throw new Error(
      `The user already holds ${existing} access keys, the AWS maximum. ` +
        `Deactivate and delete one first.`,
    );
  }
  if (existing >= 1 && !allowSecond) {
    throw new Error(
      `The user already holds ${existing} access key. Minting a second is the ` +
        `overlap step of a rotation; pass allowSecond=true if that is what ` +
        `this is, and retire the old key once consumers have moved.`,
    );
  }
}

/**
 * Write a `key` snapshot, keeping what only `create` could know.
 *
 * The secret's fingerprint and delivery address exist only in the run that
 * minted the key. A later `list` or `deactivate` sees neither, so writing its
 * snapshot as-is would erase them from the id-keyed record. Carry them forward.
 */
async function writeKey(
  context: ExecuteContext,
  r: KeyResource,
): Promise<{ name: string }> {
  if (r.secretFingerprint === null && context.readResource) {
    const prev = await context.readResource(r.accessKeyId);
    if (prev) {
      r.secretFingerprint = (prev.secretFingerprint as string | null) ?? null;
      r.deliveredTo = (prev.deliveredTo as KeyResource["deliveredTo"]) ??
        null;
    }
  }
  return await context.writeResource("key", r.accessKeyId, r);
}

/**
 * Instance name for the inventory snapshot. NOT `current`: `create` also writes
 * `key/current`, and swamp rejects two outputs with one instance name in a
 * single method execution, even across specs. The key is already minted and
 * delivered by then, so the run fails after the irreversible step.
 */
export const INVENTORY_INSTANCE = "summary";

/** Refresh `inventory/summary` from a fresh listing. */
async function writeInventory(
  context: ExecuteContext,
  userName: string,
  keys: ListedKey[],
  now: Date,
): Promise<{ name: string }> {
  return await context.writeResource("inventory", INVENTORY_INSTANCE, {
    userName,
    keyCount: keys.length,
    activeCount: keys.filter((k) => k.status === "Active").length,
    slotsFree: Math.max(0, MAX_KEYS_PER_USER - keys.length),
    accessKeyIds: keys.map((k) => k.accessKeyId),
    observedAt: now.toISOString(),
  });
}

// --- Model -------------------------------------------------------------------

/** Swappable for tests. */
export const _internal = {
  iamClient: (region: string): IamLike =>
    new IAMClient({ region }) as unknown as IamLike,
};

/** AWS IAM access key model — one instance per IAM user. */
export const model = {
  type: "@sntxrr/aws-access-key",
  description:
    "Mint, inventory, deactivate and delete AWS IAM access keys, delivering a new key straight into a named vault item",
  version: "2026.09.23.2",
  upgrades: [
    {
      toVersion: "2026.09.23.2",
      description:
        "The inventory snapshot moves from instance `current` to `summary`; `create` failed after delivering the key because `key/current` and `inventory/current` collided. No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgsSchema,
  resources: {
    "key": {
      description:
        "One access key's metadata and fingerprints. Never the secret.",
      schema: KeySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    "inventory": {
      description: "Every key the user holds as of one list call.",
      schema: InventorySchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },
  checks: {
    "valid-target": {
      description:
        "targetVault and targetItem are set together or not at all, and the item is a plain name.",
      labels: ["policy"],
      execute: (
        // Raw configuration, before defaults: either field may be absent.
        context: { globalArgs: RawGlobalArgs },
      ): { pass: boolean; errors?: string[] } => {
        const g = context.globalArgs;
        const errors: string[] = [];
        if (Boolean(g.targetVault) !== Boolean(g.targetItem)) {
          errors.push(
            "targetVault and targetItem must be set together — one without " +
              "the other gives create nowhere to write.",
          );
        }
        if (
          typeof g.targetItem === "string" && !VAULT_ITEM_RE.test(g.targetItem)
        ) {
          errors.push(
            `targetItem "${g.targetItem}" must be a plain item name: ` +
              `letters, digits and ._-, no slashes or op:// URIs.`,
          );
        }
        return errors.length > 0 ? { pass: false, errors } : { pass: true };
      },
    },
  },
  methods: {
    list: {
      description:
        "Inventory the user's access keys with status, age and last use.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const iam = _internal.iamClient(g.region);
        logger.info("Listing access keys for {user}", { user: g.userName });
        const now = new Date();
        const keys = await listKeys(iam, g.userName);
        const handles: Array<{ name: string }> = [];
        for (const k of keys) {
          const r = await toKeyResource(iam, g.userName, k, now);
          handles.push(await writeKey(context, r));
        }
        handles.push(await writeInventory(context, g.userName, keys, now));
        logger.info("User {user} holds {n} access key(s)", {
          user: g.userName,
          n: keys.length,
        });
        return { dataHandles: handles };
      },
    },
    create: {
      description:
        "Mint a new access key and write both halves into targetVault/targetItem, verified by read-back. Rolls the key back if delivery fails.",
      arguments: CreateArgsSchema,
      execute: async (
        args: z.infer<typeof CreateArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger, vaultService } = context;
        const { vaultName, item } = createPreflight(g, vaultService);
        const vault = vaultService as VaultLike;
        const iam = _internal.iamClient(g.region);

        const existing = await listKeys(iam, g.userName);
        slotCheck(existing.length, args.allowSecond);

        logger.info("Creating access key for {user}", { user: g.userName });
        const res = await iam.send(
          new CreateAccessKeyCommand({ UserName: g.userName }),
        );
        const ak = (res.AccessKey ?? {}) as Record<string, unknown>;
        const accessKeyId = ak.AccessKeyId as string | undefined;
        const secret = ak.SecretAccessKey as string | undefined;
        if (!accessKeyId || !secret) {
          // Nothing usable came back. If an id did, the key exists and must go.
          if (accessKeyId) await rollback(iam, g.userName, accessKeyId, logger);
          throw new Error(
            "CreateAccessKey returned no key material; nothing was stored.",
          );
        }
        context.redactor?.addSecret(secret);

        const keys = vaultKeys(item);
        const secretFp = await fingerprint(secret);
        const idFp = await fingerprint(accessKeyId);
        try {
          await vault.put(vaultName, keys.accessKeyIdKey, accessKeyId);
          await vault.put(vaultName, keys.secretAccessKeyKey, secret);
          // Prove it landed. A put that "succeeds" into the wrong place is the
          // failure that costs the key.
          const readId = await vault.get(vaultName, keys.accessKeyIdKey);
          const readSecret = await vault.get(
            vaultName,
            keys.secretAccessKeyKey,
          );
          if (
            (await fingerprint(readId.trim())) !== idFp ||
            (await fingerprint(readSecret.trim())) !== secretFp
          ) {
            throw new Error(
              "vault read-back does not match what was written",
            );
          }
        } catch (err) {
          await rollback(iam, g.userName, accessKeyId, logger);
          throw new Error(
            `Could not deliver the new key to vault "${vaultName}" item ` +
              `"${item}" (${(err as Error).message}); the key was deleted ` +
              `again so it does not occupy a slot.`,
          );
        }

        const now = new Date();
        const resource: KeyResource = {
          userName: g.userName,
          accessKeyId,
          status: (ak.Status as "Active" | "Inactive") ?? "Active",
          createdAt: isoOrNull(ak.CreateDate) ?? now.toISOString(),
          ageDays: 0,
          lastUsedAt: null,
          lastUsedService: null,
          lastUsedRegion: null,
          accessKeyIdFingerprint: idFp,
          secretFingerprint: secretFp,
          deliveredTo: { vault: vaultName, ...keys },
          observedAt: now.toISOString(),
        };
        const handles = [
          await context.writeResource("key", accessKeyId, resource),
          await context.writeResource("key", "current", resource),
          await writeInventory(
            context,
            g.userName,
            await listKeys(iam, g.userName),
            now,
          ),
        ];
        logger.info(
          "Created {id} for {user}; delivered to {vault}:{item} (secret fp {fp})",
          {
            id: accessKeyId,
            user: g.userName,
            vault: vaultName,
            item,
            fp: secretFp,
          },
        );
        return { dataHandles: handles };
      },
    },
    deactivate: {
      description:
        "Set one key Inactive — the reversible step before delete in a rotation.",
      arguments: KeyIdArgsSchema,
      execute: async (
        args: z.infer<typeof KeyIdArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const iam = _internal.iamClient(g.region);
        const k = await requireOwnedKey(iam, g.userName, args.accessKeyId);
        logger.info("Deactivating {id} of {user}", {
          id: args.accessKeyId,
          user: g.userName,
        });
        await iam.send(
          new UpdateAccessKeyCommand({
            UserName: g.userName,
            AccessKeyId: args.accessKeyId,
            Status: "Inactive",
          }),
        );
        // Read back rather than trusting the 200.
        const after = await requireOwnedKey(iam, g.userName, args.accessKeyId);
        if (after.status !== "Inactive") {
          throw new Error(
            `UpdateAccessKey returned but ${args.accessKeyId} still reads ${after.status}.`,
          );
        }
        logger.info("Deactivated {id} (was {status})", {
          id: args.accessKeyId,
          status: k.status,
        });
        const now = new Date();
        const r = await toKeyResource(iam, g.userName, after, now);
        return {
          dataHandles: [
            await writeKey(context, r),
            await writeInventory(
              context,
              g.userName,
              await listKeys(iam, g.userName),
              now,
            ),
          ],
        };
      },
    },
    delete: {
      description:
        "Delete one key. Refuses an Active key — deactivate it first, so a still-used key fails loudly and reversibly before it is gone.",
      arguments: KeyIdArgsSchema,
      execute: async (
        args: z.infer<typeof KeyIdArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const iam = _internal.iamClient(g.region);
        const keys = await listKeys(iam, g.userName);
        const k = keys.find((x) => x.accessKeyId === args.accessKeyId);
        if (!k) {
          logger.info("{id} is not a key of {user}; nothing to delete", {
            id: args.accessKeyId,
            user: g.userName,
          });
          return { dataHandles: [] };
        }
        if (k.status === "Active") {
          throw new Error(
            `${args.accessKeyId} is Active. Run deactivate first and confirm ` +
              `nothing broke; delete is not reversible.`,
          );
        }
        logger.info("Deleting {id} of {user}", {
          id: args.accessKeyId,
          user: g.userName,
        });
        await iam.send(
          new DeleteAccessKeyCommand({
            UserName: g.userName,
            AccessKeyId: args.accessKeyId,
          }),
        );
        const remaining = await listKeys(iam, g.userName);
        if (remaining.some((x) => x.accessKeyId === args.accessKeyId)) {
          throw new Error(
            `DeleteAccessKey returned but ${args.accessKeyId} is still listed.`,
          );
        }
        logger.info("Deleted {id}; {user} now holds {n} key(s)", {
          id: args.accessKeyId,
          user: g.userName,
          n: remaining.length,
        });
        return {
          dataHandles: [
            await writeInventory(context, g.userName, remaining, new Date()),
          ],
        };
      },
    },
  },
};

async function requireOwnedKey(
  iam: IamLike,
  userName: string,
  accessKeyId: string,
): Promise<ListedKey> {
  const k = (await listKeys(iam, userName)).find(
    (x) => x.accessKeyId === accessKeyId,
  );
  if (!k) {
    throw new Error(`${accessKeyId} is not an access key of ${userName}.`);
  }
  return k;
}

async function rollback(
  iam: IamLike,
  userName: string,
  accessKeyId: string,
  logger: Logger,
): Promise<void> {
  try {
    await iam.send(
      new DeleteAccessKeyCommand({
        UserName: userName,
        AccessKeyId: accessKeyId,
      }),
    );
    logger.warn("Rolled back {id}: deleted after failed delivery", {
      id: accessKeyId,
    });
  } catch (err) {
    if (errorName(err) === "NoSuchEntityException") return;
    logger.warn(
      "ROLLBACK FAILED: {id} exists with no stored secret — delete it by hand ({err})",
      { id: accessKeyId, err: (err as Error).message },
    );
  }
}
