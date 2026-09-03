# Releasing

## Current prerequisites

- The GitHub repository is `noz-ele/x509-http-signatures`.
- The npm package name is `@noz-ele/x509-http-signatures`.
- npm authentication and permission to publish under the `@noz-ele` scope are
  required.
- Public GitHub visibility is recommended before a public npm release so that
  users can inspect the source and npm can attach public provenance.

## First npm release

The first release establishes the package on npm. Run it interactively from a
clean checkout because npm authentication or 2FA approval is required.

```sh
npm login
npm whoami
npm ci
npm run typecheck
npm test
npm pack --dry-run
npm publish --access public
```

Confirm that `npm whoami` is a member or owner of the `noz-ele` npm
organization and is allowed to create public packages in that scope.

## Configure trusted publishing

After the package exists on npm, open its settings and add a GitHub Actions
trusted publisher with these exact values:

```text
Organization or user: noz-ele
Repository: x509-http-signatures
Workflow filename: publish.yml
Allowed action: npm publish
```

No long-lived `NPM_TOKEN` is needed. The workflow has the required
`id-token: write` permission and uses a GitHub-hosted runner. If an npm
deployment environment is added later, configure the same environment name in
both npm and the workflow.

## Subsequent releases

Start with a clean, passing `main` branch, then choose the appropriate semantic
version increment:

```sh
npm version patch
git push origin main --follow-tags
gh release create v<version> --generate-notes
```

Publishing the GitHub Release triggers `.github/workflows/publish.yml`. The
workflow verifies that the release tag exactly matches the version in
`package.json`, installs from `package-lock.json`, runs checks, and publishes
through npm trusted publishing.

Never reuse a published version. If a release fails after a version has reached
npm, fix the problem and publish a new patch version.
