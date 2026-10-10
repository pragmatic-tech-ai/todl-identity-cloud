export type AuthorizationRequestOptions =
{
    AuthorizationEndpoint: string;
    ClientId: string;
    RedirectUri: string;
    Scopes: readonly string[];
    State: string;
    Nonce: string;
    Challenge: string;
};

export class AuthorizationRequest
{
    private static readonly ResponseTypeParam = "response_type";
    private static readonly ResponseTypeCode = "code";
    private static readonly ClientIdParam = "client_id";
    private static readonly RedirectUriParam = "redirect_uri";
    private static readonly ScopeParam = "scope";
    private static readonly StateParam = "state";
    private static readonly NonceParam = "nonce";
    private static readonly CodeChallengeParam = "code_challenge";
    private static readonly CodeChallengeMethodParam = "code_challenge_method";
    private static readonly CodeChallengeMethodS256 = "S256";
    private static readonly ScopeSeparator = " ";

    public static Build(opts: AuthorizationRequestOptions): string
    {
        const url = new URL(opts.AuthorizationEndpoint);
        url.searchParams.set(AuthorizationRequest.ResponseTypeParam, AuthorizationRequest.ResponseTypeCode);
        url.searchParams.set(AuthorizationRequest.ClientIdParam, opts.ClientId);
        url.searchParams.set(AuthorizationRequest.RedirectUriParam, opts.RedirectUri);
        url.searchParams.set(AuthorizationRequest.ScopeParam, opts.Scopes.join(AuthorizationRequest.ScopeSeparator));
        url.searchParams.set(AuthorizationRequest.StateParam, opts.State);
        url.searchParams.set(AuthorizationRequest.NonceParam, opts.Nonce);
        url.searchParams.set(AuthorizationRequest.CodeChallengeParam, opts.Challenge);
        url.searchParams.set(AuthorizationRequest.CodeChallengeMethodParam, AuthorizationRequest.CodeChallengeMethodS256);
        return url.toString();
    }
}
