import { SourceTokenError, SourceTokenFailure } from "@pragmatic-tech-ai/todl-identity";
import type { SourceToken, SourceTokenRequest } from "@pragmatic-tech-ai/todl-identity";
import type { IRevocableSourceTokenProvider } from "./revocable-source-token-provider.js";

/** Source-token provider for packs that cannot exchange tokens: every request is unsupported. */
export class UnsupportedSourceTokenProvider implements IRevocableSourceTokenProvider
{
    public async Acquire(_request: SourceTokenRequest): Promise<SourceToken>
    {
        throw new SourceTokenError(SourceTokenFailure.UnsupportedPrincipal);
    }

    /** Nothing is cached, so there is nothing to forget. */
    public Forget(_realmId: string, _principalId: string): void
    {
    }
}
