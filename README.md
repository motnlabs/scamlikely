# scamlikely

A small, self-hosted Discord bot that catches impersonation and name-squatting
inside one server. It watches members join and change their profile, compares
them against a per-guild list of protected identities, and posts an alert with
a human **Ban** / **Ignore** decision. It never bans on its own.

MIT licensed. No telemetry, no hosted service, no message content log.

## Add it to a server

Two permission tiers. Pick the second only if you want the alert's Ban button.

**Post-only** - reads names and avatars, posts alerts, cannot act:

<https://discord.com/oauth2/authorize?client_id=1569778897111744532&scope=bot+applications.commands&permissions=19456>

**Post-only + one-click ban** - adds \Ban Members\ so the alert button works:

<https://discord.com/oauth2/authorize?client_id=1569778897111744532&scope=bot+applications.commands&permissions=19460>

Both request \View Channels\, \Send Messages\, \Embed Links\, and the
\pplications.commands\ scope. Nothing else: the bot never manages roles,
never reads message history, and never deletes anything. The Ban button is
hidden entirely when the bot does not hold \Ban Members\, so a post-only
install is coherent rather than a button that fails on click.

You must enable the **Server Members Intent** for your own copy in the
Developer Portal even to run it - see Deployment.
## What it catches

| Signal | Rule | Weight |
|---|---|---|
| Identical display name | Normalised equality (leet + digraph folding, accents dropped, separators removed) on names of 3+ characters | Name match |
| Near-identical display name | Damerau-Levenshtein distance 1 for names up to 6 chars, 2 for longer names; names shorter than 4 chars are not fuzzy-matched | Weak |
| Username near-match | Same edit budget after removing padding suffixes (`4u`, `4you`, `for`, `official`, `real`, `tv`, `hq`, ...) and folding leet (`0->o`, `1->l/i`, `3->e`, `4->a`, `5->s`, `7->t`, `$->s`, `@->a`); also a prefix-plus-marker rule | Strong |
| Avatar match | dHash 16x16 (256 bits); Hamming distance <= 8 counts as the same art. Survives resizing and JPEG re-encoding | Strong |
| Young account | Snowflake creation time `(id >> 22) + 1420070400000`; younger than 30 days is corroboration only, never a hit by itself | Corroboration |

Severity:

- **high** - identical display name *and* at least one of (username match,
  avatar match, young account), or username match *and* avatar match.
- **medium** - username match on its own.
- **low** - identical or near-identical display name alone, or a matching
  avatar alone.

Two moderators from different servers who merely share a common name therefore
never reach `high`. The protected user themself, bots, and short names are
excluded.

## Server admin setup (three steps)

1. **Create the application.** <https://discord.com/developers/applications> ->
   New Application -> Bot -> Reset Token. Copy the token into `.env` as
   `DISCORD_TOKEN`.
2. **Enable the Server Members intent.** In the Bot tab, turn on
   **Privileged Gateway Intents -> Server Members Intent** (`GUILD_MEMBERS`).
   Without it the bot sees joins and profile changes as empty ids.
3. **Invite it.** OAuth2 -> URL Generator: scopes `bot` and
   `applications.commands`; permissions **View Channels**, **Send Messages**,
   **Embed Links**, **Ban Members**, **Manage Roles** (needed so the ban
   respects role hierarchy). Open the generated URL and add it to the server.

Then, in the server:

```
/protect user:<the real account's id> notes:owner
/alert-channel channel:#mod-log
/scan
```

`/protect` snapshots the display name, username and avatar hash at that moment.
Re-run it if the protected person changes their avatar or name.

## Commands

| Command | What it does |
|---|---|
| `/protect <user> [notes]` | Adds or updates a protected identity (Manage Server) |
| `/protect-list` | Lists protected identities for this guild |
| `/unprotect <user>` | Removes one |
| `/scan` | Sweeps all current members against the registry, paginated with pauses; posts at most `SCAN_MAX_ALERTS` alerts, never bans |
| `/forget <user>` | Deletes every stored row for that user (privacy) |
| `/alert-channel <channel>` | Picks the alert channel; otherwise `ALERT_CHANNEL_ID`, then the guild system channel |

Alert embeds show the display name, username, user id, account age, avatar
distance (n/256), the matched protected identity, severity, signals, and the
human-readable evidence. Ban / Ignore buttons persist: Ignore silences that
subject/protected pair until severity rises, Ban records the decision. Alerts
are deduplicated for 24 hours unless severity escalates.

## Configuration

Environment variables (or `.env`, parsed by the bot itself):

| Variable | Default | Meaning |
|---|---|---|
| `DISCORD_TOKEN` | - | required |
| `ALERT_CHANNEL_ID` | system channel | fallback channel for single-guild deployments |
| `BOT_DB_PATH` | `data/scamlikely.db` | SQLite file |
| `AVATAR_DISTANCE_MAX` | `8` | dHash threshold out of 256 |
| `YOUNG_ACCOUNT_DAYS` | `30` | young-account corroboration window |
| `ALERT_DEDUPE_HOURS` | `24` | quiet period per pair |
| `SCAN_PAUSE_SECONDS` | `1.0` | sleep every 500 members during `/scan` |
| `SCAN_MAX_ALERTS` | `25` | per-scan alert cap |
| `LOG_LEVEL` | `INFO` | logging |

## Run it

Self-host from the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env        # fill in DISCORD_TOKEN
.venv/bin/python -m scamlikely.bot
```

`python scamlikely/bot.py` also works; `python -m scamlikely.bot` is the supported form.

systemd (unit included at `deploy/scamlikely.service`):

```bash
sudo useradd --system --home /opt/scamlikely scamlikely
sudo mkdir -p /opt/scamlikely /var/lib/scamlikely
sudo chown -R scamlikely:scamlikely /opt/scamlikely /var/lib/scamlikely
sudo cp deploy/scamlikely.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scamlikely
journalctl -u scamlikely -f
```

The unit assumes the checkout is at `/opt/scamlikely`, the venv at
`/opt/scamlikely/.venv`, reads `/etc/scamlikely/env`, and confines writes to
`/var/lib/scamlikely`. Adjust the paths if yours differ. Database writes under
`ProtectSystem=strict`.

## Privacy

The bot stores: guild and user ids, the display-name/username/avatar-hash
history it observes, the protected registry, and alert decisions. It does not
read message content, does not request the message-content intent, and never
downloads or keeps avatar images - only a 256-bit hash. Everything lives in one
SQLite file on the host you run. `/forget <user>` deletes the registry entry,
name history, cached avatar hash and alert rows for that user; run it for
anyone who asks. Treat `/protect-list` and the alert channel as staff-only
(Manage Server is required for the commands).

## Scale (guilds of 10k+ members)

/scan runs in two phases. Phase 1 reads display names and usernames only -
no network, no image work - and queues anyone who trips a name rule. Phase 2
downloads and hashes just those avatars, eight at a time. A 20,000-member guild
therefore costs a member-list fetch plus a handful of images, not 20,000.

The trade-off is an avatar-only clone (same art, unrelated name) is missed.
Set SCAN_ALL_AVATARS=true for one pass to cover that case: it hashes every
member once, then caches each result by avatar key so later scans cost nothing.
Do not leave it on for a large public guild.

Name churn is also high at this size, so alerts dedupe for ALERT_DEDUPE_HOURS
and /scan is capped by SCAN_MAX_ALERTS; both exist so a busy guild does not
turn the alert channel into noise nobody reads.

## Limitations

- **OAuth connections are invisible.** Discord's API does not expose a user's
  linked accounts. The lookalike X, Spotify and Reddit connections in the
  2026-11-10 case could not be read by this bot even with every scope; that
  evidence has to come from a human profile review.
- **Only guilds the bot is in.** There is no global user directory and no way
  to see members of a server the bot has not joined.
- **Display names are cheap.** Renaming takes seconds, so the checks weigh the
  username and avatar too; a lone display-name match is only `low`.
- **dHash catches the same art, not the same idea.** A redrawn or heavily
  cropped avatar will not match. An exact match with distance 0 is strong; 8 is
  deliberately permissive because Discord re-encodes and resizes avatars.
- **No historical or cross-server scan.** `/scan` walks current members only.
  Someone who joins, posts and leaves between events is caught only if the
  join or update event fires.
- **Commands are guild-scoped in behaviour, global in registration.** Discord
  can take up to an hour to show a newly synced command; re-inviting or
  restarting does not speed that up.
- **Rate limits are respected, not fought.** `/scan` is intentionally slow
  (0.05s per avatar, 1s per 500 members) and caps alerts. It never bans.

## Tests

The detection core has no discord.py imports and is tested entirely against
fixtures (synthetic avatars, no network):

```bash
python -m pytest scamlikely/tests -q
```

`scamlikely/tests/test_regression_real_case.py` encodes the real pair and the 0/256
distance, plus two negative controls.

## Licence

MIT. See `LICENSE`. Copyright (c) 2026 Motion Labs LTD (motnlabs).
