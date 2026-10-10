import { SignJWT, exportJWK, generateKeyPair } from "jose";
import type { JWK, CryptoKey } from "jose";
import type { IHttpClient } from "../http/http-client.js";

export interface MintOptions
{
    alg?: string;
    kid?: string;
    issuer?: string;
    expSecondsFromNow?: number;
}

export class FakeOidcIdp
{
    private static readonly DefaultIssuer = "https://idp.test/tenant";
    private static readonly DefaultKid = "test-key-1";
    private static readonly SigAlg = "RS256";
    private static readonly SigUse = "sig";
    private static readonly AuthorizePath = "/authorize";
    private static readonly TokenPath = "/token";
    private static readonly JwksPath = "/jwks";
    private static readonly DiscoveryPath = "/.well-known/openid-configuration";
    private static readonly NoneAlg = "none";
    private static readonly JwtTyp = "JWT";
    private static readonly Base64Url = "base64url";
    private static readonly DefaultExpSeconds = 300;

    public readonly AuthorizationEndpoint: string;
    public readonly TokenEndpoint: string;
    public readonly JwksUri: string;
    public readonly DiscoveryUrl: string;

    private constructor(
        private readonly privateKey: CryptoKey,
        private readonly publicJwk: JWK,
        private readonly kid: string,
        public readonly Issuer: string)
    {
        this.AuthorizationEndpoint = Issuer + FakeOidcIdp.AuthorizePath;
        this.TokenEndpoint = Issuer + FakeOidcIdp.TokenPath;
        this.JwksUri = Issuer + FakeOidcIdp.JwksPath;
        this.DiscoveryUrl = Issuer + FakeOidcIdp.DiscoveryPath;
    }

    public static async Create(issuer?: string): Promise<FakeOidcIdp>
    {
        const { publicKey, privateKey } = await generateKeyPair(FakeOidcIdp.SigAlg);
        const kid = FakeOidcIdp.DefaultKid;
        const jwk = await exportJWK(publicKey);
        jwk.kid = kid;
        jwk.alg = FakeOidcIdp.SigAlg;
        jwk.use = FakeOidcIdp.SigUse;
        return new FakeOidcIdp(privateKey, jwk, kid, issuer ?? FakeOidcIdp.DefaultIssuer);
    }

    public DiscoveryDocument(): object
    {
        return {
            issuer: this.Issuer,
            authorization_endpoint: this.AuthorizationEndpoint,
            token_endpoint: this.TokenEndpoint,
            jwks_uri: this.JwksUri,
        };
    }

    public Jwks(): { keys: JWK[] }
    {
        return { keys: [this.publicJwk] };
    }

    public async MintIdToken(payload: Record<string, unknown>, opts?: MintOptions): Promise<string>
    {
        const exp = Math.floor(Date.now() / 1000) + (opts?.expSecondsFromNow ?? FakeOidcIdp.DefaultExpSeconds);
        return await new SignJWT(payload)
            .setProtectedHeader({ alg: opts?.alg ?? FakeOidcIdp.SigAlg, kid: opts?.kid ?? this.kid })
            .setIssuedAt()
            .setIssuer(opts?.issuer ?? this.Issuer)
            .setExpirationTime(exp)
            .sign(this.privateKey);
    }

    public MintRawUnsigned(payload: Record<string, unknown>): string
    {
        const header = { alg: FakeOidcIdp.NoneAlg, typ: FakeOidcIdp.JwtTyp };
        return this.Encode(header) + "." + this.Encode(payload) + ".";
    }

    private Encode(value: object): string
    {
        return Buffer.from(JSON.stringify(value)).toString(FakeOidcIdp.Base64Url);
    }
}

export class FakeOidcHttpClient implements IHttpClient
{
    private static readonly UnknownUrlMessage = "FakeOidcHttpClient: unknown URL";
    private static readonly TokenFailedMessage = "FakeOidcHttpClient: token endpoint failure";

    public NextTokenResponse: unknown = null;
    public FailTokenEndpoint = false;
    public readonly PostedFields: Array<ReadonlyMap<string, string>> = [];

    public constructor(private readonly idp: FakeOidcIdp)
    {
    }

    public async GetJson(url: string): Promise<unknown>
    {
        if (url === this.idp.DiscoveryUrl)
        {
            return this.idp.DiscoveryDocument();
        }
        if (url === this.idp.JwksUri)
        {
            return this.idp.Jwks();
        }
        throw new Error(FakeOidcHttpClient.UnknownUrlMessage);
    }

    public async PostForm(url: string, fields: ReadonlyMap<string, string>): Promise<unknown>
    {
        this.PostedFields.push(fields);
        if (url !== this.idp.TokenEndpoint)
        {
            throw new Error(FakeOidcHttpClient.UnknownUrlMessage);
        }
        if (this.FailTokenEndpoint)
        {
            throw new Error(FakeOidcHttpClient.TokenFailedMessage);
        }
        return this.NextTokenResponse;
    }
}
