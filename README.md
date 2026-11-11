# todl-identity-cloud

Cloud identity provider packs (Microsoft Entra, Google, generic OIDC) for the identity framework.

## Directory sync

The Entra pack exposes `DirectorySource`, an authoritative Microsoft Graph source: it reads
group members (following `@odata.nextLink`) and user state (`accountEnabled`, 404 as deleted)
with an app-only token. Any other Graph error rejects the whole snapshot, so a partial
snapshot never deprovisions anyone. Entra principal ids are the `oid` claim, which equals the
Graph object id.

When the `apiScope` setting is present the pack also exposes `SourceTokens`, an on-behalf-of
provider that exchanges each user's stored upstream assertion for a per-user source token.

PR7: with a non-directory IdP (generic OIDC, Google), a user disabled or deleted in the IdP
keeps access until their current session expires, because nothing can tell the platform
sooner. Admins who need immediate revocation remove the user's assignments and manual team
rows, or use an IdP with a directory API. Those packs expose no directory source, so the host
uses a non-authoritative snapshot.
