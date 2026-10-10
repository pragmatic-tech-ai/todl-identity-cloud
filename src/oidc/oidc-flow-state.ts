export class OidcFlowState
{
    public constructor(
        public readonly State: string,
        public readonly Nonce: string,
        public readonly CodeVerifier: string,
        public readonly RedirectUri: string,
        public readonly ExpiresAt: Date)
    {
    }
}
