export class OidcResolvedConfig
{
    public constructor(
        public readonly DiscoveryUrl: string,
        public readonly Issuer: string,
        public readonly ClientId: string,
        public readonly RedirectUri: string,
        public readonly Scopes: readonly string[],
        public readonly SecretRef: string | null,
        public readonly ClientSecretParam: string)
    {
    }
}
