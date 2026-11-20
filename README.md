> Archived 2026-11-20: moved to pragmatic-shared, split per identity source: packages/pragmatic-identity-source-oidc, packages/pragmatic-identity-source-entra and packages/pragmatic-identity-source-google, published as @pragmatic-tech-ai/pragmatic-identity-source-oidc, @pragmatic-tech-ai/pragmatic-identity-source-entra and @pragmatic-tech-ai/pragmatic-identity-source-google.
>
> The package @pragmatic-tech-ai/todl-identity-cloud is retired. GitHub Packages does not support npm deprecate, so its published versions carry no deprecation flag; use the new package.

# todl-identity-cloud

Cloud identity provider packs (Microsoft Entra, Google, generic OIDC) for the identity framework.

## Directory sync

The Entra pack exposes `DirectorySource`, an authoritative Microsoft Graph source: it reads
group members (following `@odata.nextLink`) and user state (`accountEnabled`, 404 as deleted)
with an app-only token. Any other Graph error rejects the whole snapshot, so a partial
snapshot never deprovisions anyone. Entra principal ids are the `oid` claim, which equals the
Graph object id; Entra principal ids are lowercase object ids, and a config id in another case grants nothing. Every member of a linked group gets a state from its `accountEnabled`, so a
disabled member reached only through a group loses its team rows and is deprovisioned. A
disabled user who appears nowhere in the setting has no roles but keeps Default-Allow access to
external (connector) concepts until their session expires.

When the `apiScope` setting is present the pack also exposes `SourceTokens`, an on-behalf-of
provider that exchanges each user's stored upstream assertion for a per-user source token.
Concurrent requests for the same user share one in-flight refresh of the upstream assertion.
Hosts must call `UpstreamTokenVault.Delete` and `PerUserSourceTokenCache.Forget` for each id in
`IdpDirectorySyncResult.Deprovisioned` and on sign-out; the provider never cleans them up itself.

PR7: with a non-directory IdP (generic OIDC, Google), a user disabled or deleted in the IdP
keeps access until their current session expires, because nothing can tell the platform
sooner. Admins who need immediate revocation remove the user's assignments and manual team
rows, or use an IdP with a directory API. Those packs expose no directory source, so the host
uses a non-authoritative snapshot.
