# Hosting the relay on Fly.io

The relay is one small server (`opendrop-relay`) that keeps its data in one
folder: `relay.db` (SQLite: accounts, devices, tokens), `relay.key` (the
master key for the inbox) and `inbox/` (encrypted files). On Fly.io that is
one machine with a 1 GB volume mounted at `/data`. Fly gives it HTTPS at
`https://<app>.fly.dev`, which is what claude.ai and ChatGPT need to reach
the hosted MCP server at `/mcp`.

OpenDrop's own relay runs as the Fly app `opendrop-relay-aj` at
`https://opendrop-relay-aj.fly.dev` (`opendrop-relay` was taken). The
commands below use `opendrop-relay`; swap in your app's name.

The files: `relay/Dockerfile` (multi-stage Rust build, about 128 MB image)
and `fly.toml` at the repo root.

## First deploy

From the repo root, signed in to Fly (`fly auth login`):

```sh
# 1. Create the app in your organization (pick another name if it's taken,
#    and put the same name in fly.toml's `app` line).
fly apps create opendrop-relay --org <your-org>

# 2. The volume for /data, in the same region as fly.toml's primary_region.
fly volumes create relay_data --size 1 --region sjc --app opendrop-relay --yes

# 3. Build and start exactly one machine (SQLite must not be shared).
fly deploy --ha=false

# 4. Check it.
curl https://opendrop-relay.fly.dev/healthz
```

The relay works out its public URL from `FLY_APP_NAME`
(`https://<app>.fly.dev`). For a custom domain, set
`fly secrets set OPENDROP_RELAY_PUBLIC_URL=https://relay.example.com`.

## Using it

```sh
opendrop relay login you@example.com --relay https://opendrop-relay.fly.dev
```

Sign-in links are emailed through [Resend](https://resend.com) once you set
its key (and, with a verified domain of your own, the sender):

```sh
fly secrets set RESEND_API_KEY=re_... \
  OPENDROP_RELAY_EMAIL_FROM="OpenDrop <signin@your-domain>" --app opendrop-relay
```

Without a domain, leave out `OPENDROP_RELAY_EMAIL_FROM`: Resend's shared
sender then only delivers to the address the Resend account was made with.
Without a key, or when sending fails, links are printed to the relay's log
(`fly logs --app opendrop-relay`).

## Later deploys and care

- `fly deploy` from the repo root rebuilds and replaces the machine; the
  volume (and so every account and inbox file) is kept.
- Fly snapshots volumes daily and keeps them for 5 days by default
  (`fly volumes snapshots list <volume-id>`).
- Losing `relay.key` makes any inbox files unreadable (they expire within
  24 hours anyway); losing `relay.db` signs every device out.
- Don't scale past one machine: `fly scale count 1`.
