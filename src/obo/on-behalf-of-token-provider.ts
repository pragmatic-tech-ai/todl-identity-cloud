import { decodeJwt } from "jose";
import {
    PerUserSourceTokenCache,
    PresentedSecret,
    SourceToken,
    SourceTokenError,
    SourceTokenFailure,
    SystemPrincipal,
} from "@pragmatic-tech-ai/todl-identity";
import type { ISecretStore, ISourceTokenProvider, SourceTokenRequest } from "@pragmatic-tech-ai/todl-identity";
import type { IHttpClient } from "../http/http-client.js";
import type { OidcDiscovery } from "../oidc/oidc-discovery.js";
import type { OidcResolvedConfig } from "../oidc/oidc-resolved-config.js";
import { UpstreamTokens } from "./upstream-token-vault.js";
import type { UpstreamTokenVault } from "./upstream-token-vault.js";

export interface OnBehalfOfTokenProviderOptions
{
    Http: IHttpClient;
    Discovery: OidcDiscovery;
    Resolved: OidcResolvedConfig;
    Secrets: ISecretStore;
    Vault: UpstreamTokenVault;
    ApiScope: string;
    Cache?: PerUserSourceTokenCache;
    now?: () => Date;
}

export class OnBehalfOfTokenProvider implements ISourceTokenProvider
{
    private static readonly SkewMs = 60_000;
    private static readonly GrantTypeParam = "grant_type";
    private static readonly GrantTypeJwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static readonly GrantTypeRefresh = "refresh_token";
    private static readonly ClientIdParam = "client_id";
    private static readonly ClientSecretParam = "client_secret";
    private static readonly AssertionParam = "assertion";
    private static readonly ScopeParam = "scope";
    private static readonly RefreshTokenParam = "refresh_token";
    private static readonly RequestedTokenUseParam = "requested_token_use";
    private static readonly OnBehalfOf = "on_behalf_of";
    private static readonly AccessTokenField = "access_token";
    private static readonly RefreshTokenField = "refresh_token";
    private static readonly ExpiresInField = "expires_in";
    private static readonly MsPerSecond = 1000;

    private readonly cache: PerUserSourceTokenCache;
    private readonly refreshes = new Map<string, Promise<UpstreamTokens>>();
    private readonly now: () => Date;

    public constructor(private readonly opts: OnBehalfOfTokenProviderOptions)
    {
        this.cache = opts.Cache ?? new PerUserSourceTokenCache();
        this.now = opts.now ?? (() => new Date());
    }

    public async Acquire(request: SourceTokenRequest): Promise<SourceToken>
    {
        if (SystemPrincipal.IsId(request.PrincipalId, request.TenantId))
        {
            throw new SourceTokenError(SourceTokenFailure.UnsupportedPrincipal);
        }

        const cached = this.cache.Get(request, this.now());
        if (cached !== undefined) return cached;

        let tokens = await this.opts.Vault.Get(request.TenantId, request.PrincipalId);
        if (tokens === null)
        {
            throw new SourceTokenError(SourceTokenFailure.NoUpstreamSession);
        }

        try
        {
            if (this.IsExpiring(tokens.AccessToken))
            {
                if (tokens.RefreshToken === null)
                {
                    throw new SourceTokenError(SourceTokenFailure.NoUpstreamSession);
                }
                tokens = await this.SharedRefresh(request, tokens.RefreshToken);
            }
            const token = await this.Exchange(request, tokens.AccessToken);
            this.cache.Put(request, token);
            return token;
        }
        catch (e)
        {
            if (e instanceof SourceTokenError) throw e;
            throw new SourceTokenError(SourceTokenFailure.ExchangeRejected);
        }
    }

    private IsExpiring(assertion: string): boolean
    {
        const exp = this.ExpiryOf(assertion);
        return exp !== null && exp.getTime() - OnBehalfOfTokenProvider.SkewMs <= this.now().getTime();
    }

    private ExpiryOf(jwt: string): Date | null
    {
        try
        {
            const exp = decodeJwt(jwt).exp;
            return typeof exp === "number" ? new Date(exp * OnBehalfOfTokenProvider.MsPerSecond) : null;
        }
        catch
        {
            return null;
        }
    }

    /** One in-flight refresh per (tenant, principal): concurrent callers share it, and it is cleared once it settles. */
    private SharedRefresh(request: SourceTokenRequest, refreshToken: string): Promise<UpstreamTokens>
    {
        const key = JSON.stringify([request.TenantId, request.PrincipalId]);
        let pending = this.refreshes.get(key);
        if (pending === undefined)
        {
            const started = this.Refresh(request, refreshToken);
            const clear = (): void => { if (this.refreshes.get(key) === started) this.refreshes.delete(key); };
            started.then(clear, clear);
            this.refreshes.set(key, started);
            pending = started;
        }
        return pending;
    }

    private async Refresh(request: SourceTokenRequest, refreshToken: string): Promise<UpstreamTokens>
    {
        const fields = await this.ClientFields();
        fields.set(OnBehalfOfTokenProvider.GrantTypeParam, OnBehalfOfTokenProvider.GrantTypeRefresh);
        fields.set(OnBehalfOfTokenProvider.RefreshTokenParam, refreshToken);
        fields.set(OnBehalfOfTokenProvider.ScopeParam, this.opts.ApiScope);
        const response = await this.PostToken(fields);
        const access = response[OnBehalfOfTokenProvider.AccessTokenField];
        if (typeof access !== "string") throw new SourceTokenError(SourceTokenFailure.ExchangeRejected);
        const next = response[OnBehalfOfTokenProvider.RefreshTokenField];
        const refreshed = new UpstreamTokens(access, typeof next === "string" ? next : refreshToken);
        await this.opts.Vault.Put(request.TenantId, request.PrincipalId, refreshed);
        return refreshed;
    }

    private async Exchange(request: SourceTokenRequest, assertion: string): Promise<SourceToken>
    {
        const fields = await this.ClientFields();
        fields.set(OnBehalfOfTokenProvider.GrantTypeParam, OnBehalfOfTokenProvider.GrantTypeJwtBearer);
        fields.set(OnBehalfOfTokenProvider.AssertionParam, assertion);
        fields.set(OnBehalfOfTokenProvider.ScopeParam, request.Resource);
        fields.set(OnBehalfOfTokenProvider.RequestedTokenUseParam, OnBehalfOfTokenProvider.OnBehalfOf);
        const response = await this.PostToken(fields);
        const access = response[OnBehalfOfTokenProvider.AccessTokenField];
        if (typeof access !== "string") throw new SourceTokenError(SourceTokenFailure.ExchangeRejected);
        const expiresAt = this.ExpiryOf(access) ?? this.FromExpiresIn(response[OnBehalfOfTokenProvider.ExpiresInField]);
        return new SourceToken(request.Resource, new PresentedSecret(access), expiresAt);
    }

    private FromExpiresIn(expiresIn: unknown): Date
    {
        if (typeof expiresIn !== "number") throw new SourceTokenError(SourceTokenFailure.ExchangeRejected);
        return new Date(this.now().getTime() + expiresIn * OnBehalfOfTokenProvider.MsPerSecond);
    }

    private async ClientFields(): Promise<Map<string, string>>
    {
        const resolved = this.opts.Resolved;
        const secret = resolved.SecretRef === null ? null : await this.opts.Secrets.Get(resolved.SecretRef);
        if (secret === null) throw new SourceTokenError(SourceTokenFailure.ExchangeRejected);
        const fields = new Map<string, string>();
        fields.set(OnBehalfOfTokenProvider.ClientIdParam, resolved.ClientId);
        fields.set(OnBehalfOfTokenProvider.ClientSecretParam, secret);
        return fields;
    }

    private async PostToken(fields: ReadonlyMap<string, string>): Promise<Record<string, unknown>>
    {
        const endpoints = await this.opts.Discovery.Endpoints(this.opts.Resolved.DiscoveryUrl);
        const response = await this.opts.Http.PostForm(endpoints.TokenEndpoint, fields);
        if (typeof response !== "object" || response === null) throw new SourceTokenError(SourceTokenFailure.ExchangeRejected);
        return response as Record<string, unknown>;
    }
}
