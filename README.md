# ALI VPN Panel — Vercel deployment

Clean deployment package for Vercel. No API keys, preconfigured admin password, saved sessions, or local panel data are included.

## Requirements
- Vercel Python runtime
- Upstash Redis REST database for persistent state
- Environment variables configured in the Vercel project

## First deployment
1. Attach an Upstash Redis database to the Vercel project and make its REST URL/token available to the runtime.
2. Set `ALI_VPN_SETUP_TOKEN` to a strong, random, private value (at least 32 characters).
3. Deploy, then complete the one-time administrator setup flow.
4. Remove `ALI_VPN_SETUP_TOKEN` after the administrator has been created.
5. Enter your own provider API keys only in the panel settings.

## Security
Never commit `.env`, API keys, session files, database dumps, or backups. Keep repository visibility private for a management panel where possible. API keys stored in application data are not automatically encrypted by this README's instructions.

## Status
This repository is being populated with the clean Vercel-targeted project files. Live Vercel/Upstash/provider integration still requires verification in your own accounts.
