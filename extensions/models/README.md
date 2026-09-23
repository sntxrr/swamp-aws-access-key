# @sntxrr/aws-access-key

Mint, inventory, deactivate and delete AWS IAM access keys, and deliver a new
key straight into a named vault item.

| | |
| --- | --- |
| Model | `@sntxrr/aws-access-key` — one instance per IAM user |
| Methods | `list`, `create`, `deactivate`, `delete` |
| Writes | `key` (metadata + fingerprints, plus a `current` alias from `create`), `inventory` |
| Delivers | `<targetItem>/access-key-id` and `<targetItem>/secret-access-key` in `targetVault` |
| Auth | AWS SDK default credential chain |

## Why this exists

`@swamp/aws/iam` manages users and their policies through Cloud Control, but
there is no access key type: CloudFormation's `AWS::IAM::AccessKey` only hands
the secret back once, as a stack output, so Cloud Control cannot model it. The
one step that produces a secret was left as the one step done by hand. This
model is that step, and it pairs with `@swamp/aws/iam/user` and
`@swamp/aws/iam/user-policy`.

## Where the secret goes

The secret is disclosed exactly once. `create` therefore:

1. checks, **before calling AWS**, that `targetVault` exists in the repo and the
   user has a free slot;
2. mints the key and registers the secret with swamp's redactor;
3. writes `<targetItem>/access-key-id` and `<targetItem>/secret-access-key`
   into `targetVault`;
4. reads both back and compares SHA-256 fingerprints;
5. **deletes the new key again** if step 3 or 4 fails — a key whose secret was
   lost still occupies one of the user's two slots.

Nothing the model writes to swamp's datastore contains the secret. The `key`
resource records the id, status, dates, last use, the vault addresses it was
delivered to, and a 12-hex fingerprint of each half — enough to prove a
rotation landed without printing either value.

A sensitive resource field would also vault the secret, but under a key swamp
derives from the model id and field path, in the repo's default vault. A
consumer outside swamp — a shell script running
`op read op://<vault>/<item>/secret-access-key`, say — needs an address a human
chose. That is why delivery goes through the method's vault service instead.

With the `@swamp/1password` vault, the item is created as a Secure Note if it
does not exist. That backend passes the value to the `op` CLI as an argument, so
it is briefly visible in the local process list; use a Connect-backed vault if
that matters on your host.

## Two keys, and why `create` is reluctant about the second

AWS allows two access keys per user. `create` always refuses at two, and
refuses at one unless `allowSecond: true` — a second key is how a rotation
overlaps, but an unintended second key is how a leaked first key survives what
was meant to be its rotation.

`delete` refuses an **Active** key. Deactivate first, watch for breakage, then
delete: `deactivate` is reversible and `delete` is not.

## Example

```yaml
type: "@sntxrr/aws-access-key"
name: heron-state-key
globalArguments:
  userName: heron-state
  targetVault: team-1password
  targetItem: heron-state
```

```bash
swamp model @sntxrr/aws-access-key method run list   heron-state-key
swamp model @sntxrr/aws-access-key method run create heron-state-key
# rotation
swamp model @sntxrr/aws-access-key method run create heron-state-key --input allowSecond=true
#   ... move consumers, prove them ...
swamp model @sntxrr/aws-access-key method run deactivate heron-state-key --input accessKeyId=AKIA...
swamp model @sntxrr/aws-access-key method run delete     heron-state-key --input accessKeyId=AKIA...
```

## Permissions

The principal running `create` needs `iam:ListAccessKeys`,
`iam:GetAccessKeyLastUsed`, `iam:CreateAccessKey`, `iam:UpdateAccessKey` and
`iam:DeleteAccessKey` on the target user. A principal that can mint keys for a
user can act as that user, so this should be an administrative identity used
interactively, not the one your scheduled automation runs as.
