import { randomBytes } from "node:crypto";
import { jwtVerify } from "jose";
import type { JWTPayload } from "jose";
import { AuthMethod, AuthenticatedResult, RejectedResult } from "@pragmatic-tech-ai/todl-identity";
import type {
    AuthenticationResult,
    Credential,
    IAuthenticator,
    IdentityConfig,
    ISecretStore,
    PresentedSecret,
    Tenant,
} from "@pragmatic-tech-ai/todl-identity";
import type { IHttpClient } from "../http/http-client.js";
import type { OidcDiscovery } from "./oidc-discovery.js";
import type { JwksCache } from "./jwks-cache.js";
import type { IOidcFlowStateStore } from "./flow-state-store.js";
import type { ClaimsMapper } from "../claims/claims-mapper.js";
import type { OidcResolvedConfig } from "./oidc-resolved-config.js";
import { PkceChallenge } from "./pkce-challenge.js";
import { OidcFlowState } from "./oidc-flow-state.js";
import { AuthorizationRequest } from "./authorization-request.js";

export interface OidcAuthenticatorOptions
{
    Http: IHttpClient;
    Discovery: OidcDiscovery;
    Jwks: JwksCache;
    FlowStates: IOidcFlowStateStore;
    Secrets: ISecretStore;
    Claims: ClaimsMapper;
    Config: IdentityConfig;
    Resolved: OidcResolvedConfig;
    now?: () => Date;
}

export class OidcAuthenticator implements IAuthenticator
{
    private static readonly StateBytes = 32;
    private static readonly RandomEncoding = "base64url";
    private static readonly FlowTtlMs = 600_000;
    private static readonly RejectionReason = "authentication failed";
    private static readonly GrantTypeParam = "grant_type";
    private static readonly GrantTypeAuthorizationCode = "authorization_code";
    private static readonly CodeParam = "code";
    private static readonly CodeVerifierParam = "code_verifier";
    private static readonly RedirectUriParam = "redirect_uri";
    private static readonly ClientIdParam = "client_id";
    private static readonly IdTokenField = "id_token";
    private static readonly NonceClaim = "nonce";
    private static readonly AllowedAlgs: string[] = ["RS256", "ES256"];
    private static readonly ClockToleranceSec = 60;
    private static readonly NoMatchingKeyCode = "ERR_JWKS_NO_MATCHING_KEY";

    public readonly Method = AuthMethod.Oidc;

    private readonly now: () => Date;

    public constructor(private readonly opts: OidcAuthenticatorOptions)
    {
        this.now = opts.now ?? (() => new Date());
    }

    public async BeginAuthorization(_tenant: Tenant): Promise<{ Url: string; State: string }>
    {
        const resolved = this.opts.Resolved;
        const endpoints = await this.opts.Discovery.Endpoints(resolved.DiscoveryUrl);
        const pkce = PkceChallenge.Create();
        const state = randomBytes(OidcAuthenticator.StateBytes).toString(OidcAuthenticator.RandomEncoding);
        const nonce = randomBytes(OidcAuthenticator.StateBytes).toString(OidcAuthenticator.RandomEncoding);
        const expiresAt = new Date(this.now().getTime() + OidcAuthenticator.FlowTtlMs);
        await this.opts.FlowStates.Put(new OidcFlowState(state, nonce, pkce.Verifier, resolved.RedirectUri, expiresAt));
        const url = AuthorizationRequest.Build({
            AuthorizationEndpoint: endpoints.AuthorizationEndpoint,
            ClientId: resolved.ClientId,
            RedirectUri: resolved.RedirectUri,
            Scopes: resolved.Scopes,
            State: state,
            Nonce: nonce,
            Challenge: pkce.Challenge,
        });
        return { Url: url, State: state };
    }

    public async Authenticate(credential: Credential, presented: PresentedSecret, tenant: Tenant): Promise<AuthenticationResult>
    {
        const flow = await this.opts.FlowStates.Take(credential.Reference);
        if (flow === null)
        {
            return this.Reject();
        }

        try
        {
            const resolved = this.opts.Resolved;
            const endpoints = await this.opts.Discovery.Endpoints(resolved.DiscoveryUrl);

            const fields = new Map<string, string>();
            fields.set(OidcAuthenticator.GrantTypeParam, OidcAuthenticator.GrantTypeAuthorizationCode);
            fields.set(OidcAuthenticator.CodeParam, presented.Reveal());
            fields.set(OidcAuthenticator.CodeVerifierParam, flow.CodeVerifier);
            fields.set(OidcAuthenticator.RedirectUriParam, resolved.RedirectUri);
            fields.set(OidcAuthenticator.ClientIdParam, resolved.ClientId);
            if (resolved.SecretRef !== null)
            {
                const secret = await this.opts.Secrets.Get(resolved.SecretRef);
                if (secret !== null)
                {
                    fields.set(resolved.ClientSecretParam, secret);
                }
            }

            const tokenResponse = await this.opts.Http.PostForm(endpoints.TokenEndpoint, fields);
            const idToken = (tokenResponse as Record<string, unknown> | null)?.[OidcAuthenticator.IdTokenField];
            if (typeof idToken !== "string")
            {
                return this.Reject();
            }

            const verifyOptions = {
                issuer: resolved.Issuer,
                audience: resolved.ClientId,
                algorithms: OidcAuthenticator.AllowedAlgs,
                clockTolerance: OidcAuthenticator.ClockToleranceSec,
            };
            let payload: JWTPayload;
            try
            {
                ({ payload } = await jwtVerify(idToken, await this.opts.Jwks.KeySet(endpoints.JwksUri), verifyOptions));
            }
            catch (e)
            {
                if (!this.IsNoMatchingKey(e))
                {
                    return this.Reject();
                }
                ({ payload } = await jwtVerify(idToken, await this.opts.Jwks.Refresh(endpoints.JwksUri), verifyOptions));
            }

            if (payload[OidcAuthenticator.NonceClaim] !== flow.Nonce)
            {
                return this.Reject();
            }

            const principal = this.opts.Claims.Map(payload as Record<string, unknown>, tenant, this.opts.Config);
            return new AuthenticatedResult(principal);
        }
        catch
        {
            return this.Reject();
        }
    }

    private IsNoMatchingKey(e: unknown): boolean
    {
        return (e as { code?: string } | null)?.code === OidcAuthenticator.NoMatchingKeyCode;
    }

    private Reject(): RejectedResult
    {
        return new RejectedResult(OidcAuthenticator.RejectionReason);
    }
}
