import type { ISourceTokenProvider } from "@pragmatic-tech-ai/todl-identity";

/**
 * A source-token provider that caches per-user exchanged tokens and can be told to drop one user's cached entry
 * (deprovisioning, sign-out: ruling R34). The server's revoke path (CallerCredentials.Revoke) calls {@link Forget}
 * so a deprovisioned or signed-out user's cached source credential is not served during the window before it expires.
 */
export interface IRevocableSourceTokenProvider extends ISourceTokenProvider
{
    /** Drops every cached entry of `principalId` in `tenantId`; the next request for that user re-fetches. */
    Forget(tenantId: string, principalId: string): void;
}
