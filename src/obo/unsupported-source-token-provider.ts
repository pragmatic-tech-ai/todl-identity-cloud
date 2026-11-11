import { SourceTokenError, SourceTokenFailure } from "@pragmatic-tech-ai/todl-identity";
import type { ISourceTokenProvider, SourceToken, SourceTokenRequest } from "@pragmatic-tech-ai/todl-identity";

/** Source-token provider for packs that cannot exchange tokens: every request is unsupported. */
export class UnsupportedSourceTokenProvider implements ISourceTokenProvider
{
    public async Acquire(_request: SourceTokenRequest): Promise<SourceToken>
    {
        throw new SourceTokenError(SourceTokenFailure.UnsupportedPrincipal);
    }
}
