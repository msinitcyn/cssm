# Phase 2: Marketplace Publishing

## Checklist

[x] Create Azure DevOps account (https://dev.azure.com)
[x] Generate Personal Access Token
  - Navigate to: https://dev.azure.com/[org]/_usersSettings/tokens
  - Scope: **Marketplace (Publish)** (required)
  - Expiration: 1 year recommended
  - Copy token (shown only once)
[x] Add token to GitHub Secrets
  - Repo settings → Secrets → Actions → New secret
  - Name: `VSCE_PAT`
  - Value: [paste token]
[x] Update workflow - add marketplace publishing step:
  ```yaml
  - name: Publish to VS Code Marketplace
    run: |
      cd vscode-extension
      npx vsce publish -p ${{ secrets.VSCE_PAT }}
  ```
[x] Test with real tag push
[x] Verify extension published to marketplace

---

## Notes

- Token must have "Marketplace (Publish)" scope
- Publisher ID in package.json must match marketplace publisher (currently "msin")
- Token is encrypted in GitHub Secrets (never visible in logs)
