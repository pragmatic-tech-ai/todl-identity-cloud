export class OidcEndpoints
{
    public constructor(
        public readonly Issuer: string,
        public readonly AuthorizationEndpoint: string,
        public readonly TokenEndpoint: string,
        public readonly JwksUri: string)
    {
    }
}
