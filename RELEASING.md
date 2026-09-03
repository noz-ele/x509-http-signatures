# Releasing

## Prerequisites

- The GitHub repository is `noz-ele/x509-http-signatures`.
- The npm package name is `@noz-ele/x509-http-signatures`.
- npm authentication and permission to publish under the `@noz-ele` scope are
  required.
- The GitHub repository and npm package are public.

## Manual npm release

Run releases interactively from a clean checkout because npm authentication or
2FA approval may be required. Choose the appropriate semantic version increment
and replace `<version>` below with the resulting version.

```sh
npm login
npm whoami
npm ci
npm run typecheck
npm test
npm pack --dry-run
npm version patch
git push origin main --follow-tags
npm publish --access public
gh release create v<version> --verify-tag --generate-notes
```

Confirm that `npm whoami` is a member or owner of the `noz-ele` npm
organization and is allowed to publish public packages in that scope. Verify
the published version with:

```sh
npm view @noz-ele/x509-http-signatures version dist-tags.latest
```

Never reuse a published version. If a release fails after a version has reached
npm, fix the problem and publish a new patch version.
