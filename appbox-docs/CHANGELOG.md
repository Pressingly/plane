# Changelog

Changes to `Pressingly/plane`, by release tag.

Tags follow the release pipeline: `vYY.MM.N-rc.N` builds the sandbox image, `vYY.MM.N` the prod image.

Every PR into `foss-sandbox` adds its entry under **Unreleased**. When a tag is cut, rename that heading to the
tag and date and start a new **Unreleased** section. Put anything an operator has to act on under
**Behaviour changes**.

## Unreleased

### Added

- `DELETE /api/v1/users/me/api-tokens/current/` lets an API token revoke itself with only its `X-Api-Key`. It
  soft-deletes exactly the token that authenticated the request and returns 204. No session is accepted, and a
  missing, invalid or already revoked key gets 401 (other v1 routes still answer a rejected key with 403).
  ([FOSS-835](https://pm.moneta.askii.ai/moneta/browse/FOSS-835/))
