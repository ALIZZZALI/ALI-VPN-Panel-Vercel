# ALI VPN Panel — Vercel deployment

**Current state:** this repository contains the upload helper, not the full application source yet. The clean source bundle is available in the ChatGPT conversation as `ALI-VPN-Panel-Vercel-Ready.zip`.

## Publish the clean source to this repository

1. Download `ALI-VPN-Panel-Vercel-Ready.zip` from the ChatGPT conversation.
2. Download [Push-ALI-VPN-Panel-To-GitHub.ps1](https://raw.githubusercontent.com/ALIZZZALI/ALI-VPN-Panel-Vercel/main/Push-ALI-VPN-Panel-To-GitHub.ps1).
3. Put both files in the same folder on your Windows PC.
4. Open PowerShell in that folder and run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Push-ALI-VPN-Panel-To-GitHub.ps1
   ```
5. Follow the prompts. Git may ask you to authenticate with GitHub. The script checks the ZIP contents and refuses to upload obvious local data, real `.env` files, or key/database files.

The script copies the source from the ZIP into a fresh clone of this repository and pushes a commit to `main`. It does not set API keys or an administrator password.

## Vercel configuration after source is published

- Connect an Upstash Redis REST database to the Vercel project.
- Configure the Redis REST URL/token as environment variables.
- Set `ALI_VPN_SETUP_TOKEN` to a random private value of at least 32 characters before the first deployment.
- Complete initial administrator setup, then remove `ALI_VPN_SETUP_TOKEN`.
- Enter your provider API keys inside the panel settings after deployment.

## Security note

This repository is currently **public**. A VPN management panel is usually better kept in a private repository. Never commit API keys, `.env`, session files, database dumps, or backups. The application’s live Vercel/Upstash/provider integration still needs verification in your own accounts.
