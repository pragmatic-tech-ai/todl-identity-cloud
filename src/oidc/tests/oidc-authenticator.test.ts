import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
    AuthMethod,
    AuthenticatedResult,
    Credential,
    DelegationDepth,
    IdentityConfig,
    PresentedSecret,
    RejectedResult,
    Tenant,
    TenantKind,
} from "@pragmatic-tech-ai/todl-identity";
import type { AuthenticationResult, ISecretStore } from "@pragmatic-tech-ai/todl-identity";
import { OidcAuthenticator } from "../oidc-authenticator.js";
import { OidcResolvedConfig } from "../oidc-resolved-config.js";
import { OidcDiscovery } from "../oidc-discovery.js";
import { JwksCache } from "../jwks-cache.js";
import { InMemoryOidcFlowStateStore } from "../flow-state-store.js";
import { ClaimsMapper } from "../../claims/claims-mapper.js";
import { ClaimArrayGroupStrategy } from "../../claims/group-strategy.js";
import { FakeOidcIdp, FakeOidcHttpClient } from "../../testing/fake-oidc-idp.js";
import type { MintOptions } from "../../testing/fake-oidc-idp.js";

class MapSecretStore implements ISecretStore
{
    private readonly map = new Map<string, string>();

    public async Get(reference: string): Promise<string | null>
    {
        return this.map.get(reference) ?? null;
    }

    public async Put(reference: string, secret: string): Promise<void>
    {
        this.map.set(reference, secret);
    }

    public async Delete(reference: string): Promise<void>
    {
        this.map.delete(reference);
    }
}

interface LoginOverrides
{
    payload?: Record<string, unknown>;
    mintOpts?: MintOptions;
    state?: string;
    code?: string;
}

class Fixture
{
    public static readonly ClientId = "client-1";
    public static readonly RedirectUri = "https://app.test/cb";
    public static readonly DefaultCode = "auth-code";
    public static readonly SecretRef = "secret-ref";
    public static readonly SecretValue = "s3cr3t-value-xyz";

    public readonly Tenant = new Tenant("t1", TenantKind.Saas, "Tenant One");

    private constructor(
        public readonly Idp: FakeOidcIdp,
        public readonly Http: FakeOidcHttpClient,
        public readonly Store: InMemoryOidcFlowStateStore,
        public readonly Auth: OidcAuthenticator)
    {
    }

    public static async Create(secretRef: string | null = null): Promise<Fixture>
    {
        const idp = await FakeOidcIdp.Create();
        const http = new FakeOidcHttpClient(idp);
        const store = new InMemoryOidcFlowStateStore();
        const secrets = new MapSecretStore();
        await secrets.Put(Fixture.SecretRef, Fixture.SecretValue);
        const resolved = new OidcResolvedConfig(
            idp.DiscoveryUrl, idp.Issuer, Fixture.ClientId, Fixture.RedirectUri, ["openid", "email"], secretRef, "client_secret");
        const auth = new OidcAuthenticator({
            Http: http,
            Discovery: new OidcDiscovery(http),
            Jwks: new JwksCache(http),
            FlowStates: store,
            Secrets: secrets,
            Claims: new ClaimsMapper(new Map([["email", "email"]]), new ClaimArrayGroupStrategy("groups")),
            Config: new IdentityConfig("pack", DelegationDepth.AuthnDirectory, new Map(), new Map(), new Map()),
            Resolved: resolved,
        });
        return new Fixture(idp, http, store, auth);
    }

    public async CompleteLogin(overrides: LoginOverrides = {}): Promise<{ Result: AuthenticationResult; State: string }>
    {
        const { State } = await this.Auth.BeginAuthorization(this.Tenant);
        const flow = this.Store.Peek(State)!;
        const payload = {
            sub: "u1",
            aud: Fixture.ClientId,
            nonce: flow.Nonce,
            email: "a@x.io",
            groups: ["g1"],
            ...overrides.payload,
        };
        this.Http.NextTokenResponse = { id_token: await this.Idp.MintIdToken(payload, overrides.mintOpts), token_type: "Bearer" };
        const result = await this.Auth.Authenticate(
            new Credential(AuthMethod.Oidc, overrides.state ?? State),
            new PresentedSecret(overrides.code ?? Fixture.DefaultCode),
            this.Tenant);
        return { Result: result, State };
    }

    public Reason(result: AuthenticationResult): string
    {
        assert.ok(result instanceof RejectedResult);
        return result.Reason;
    }
}

describe("OidcAuthenticator", () =>
{
    test("happy path", async () =>
    {
        const f = await Fixture.Create();
        const { Result } = await f.CompleteLogin();
        assert.ok(Result instanceof AuthenticatedResult);
        assert.equal(Result.Principal.Id, "u1");
        assert.equal(Result.Principal.Claim("email"), "a@x.io");
        assert.deepEqual(Result.Principal.Groups, ["g1"]);
    });

    test("unknown state rejects before any network call", async () =>
    {
        const f = await Fixture.Create();
        const result = await f.Auth.Authenticate(new Credential(AuthMethod.Oidc, "no-such-state"), new PresentedSecret("x"), f.Tenant);
        assert.ok(result instanceof RejectedResult);
        assert.equal(f.Http.PostedFields.length, 0);
    });

    test("replayed state rejects", async () =>
    {
        const f = await Fixture.Create();
        const first = await f.CompleteLogin();
        assert.ok(first.Result instanceof AuthenticatedResult);
        const replay = await f.Auth.Authenticate(new Credential(AuthMethod.Oidc, first.State), new PresentedSecret(Fixture.DefaultCode), f.Tenant);
        assert.ok(replay instanceof RejectedResult);
    });

    test("nonce mismatch rejects", async () =>
    {
        const f = await Fixture.Create();
        const { Result } = await f.CompleteLogin({ payload: { nonce: "wrong-nonce" } });
        assert.ok(Result instanceof RejectedResult);
    });

    test("wrong aud rejects", async () =>
    {
        const f = await Fixture.Create();
        const { Result } = await f.CompleteLogin({ payload: { aud: "other-client" } });
        assert.ok(Result instanceof RejectedResult);
    });

    test("wrong iss rejects", async () =>
    {
        const f = await Fixture.Create();
        const { Result } = await f.CompleteLogin({ mintOpts: { issuer: "https://evil.example/x" } });
        assert.ok(Result instanceof RejectedResult);
    });

    test("expired rejects", async () =>
    {
        const f = await Fixture.Create();
        const { Result } = await f.CompleteLogin({ mintOpts: { expSecondsFromNow: -120 } });
        assert.ok(Result instanceof RejectedResult);
    });

    test("alg none rejects", async () =>
    {
        const f = await Fixture.Create();
        const { State } = await f.Auth.BeginAuthorization(f.Tenant);
        const flow = f.Store.Peek(State)!;
        f.Http.NextTokenResponse = {
            id_token: f.Idp.MintRawUnsigned({ sub: "u1", aud: Fixture.ClientId, iss: f.Idp.Issuer, nonce: flow.Nonce }),
        };
        const result = await f.Auth.Authenticate(new Credential(AuthMethod.Oidc, State), new PresentedSecret(Fixture.DefaultCode), f.Tenant);
        assert.ok(result instanceof RejectedResult);
    });

    test("token endpoint error rejects", async () =>
    {
        const f = await Fixture.Create();
        f.Http.FailTokenEndpoint = true;
        const { State } = await f.Auth.BeginAuthorization(f.Tenant);
        const result = await f.Auth.Authenticate(new Credential(AuthMethod.Oidc, State), new PresentedSecret(Fixture.DefaultCode), f.Tenant);
        assert.ok(result instanceof RejectedResult);
    });

    test("all rejection reasons are identical", async () =>
    {
        const f = await Fixture.Create();
        const results = [
            (await f.CompleteLogin({ payload: { nonce: "wrong-nonce" } })).Result,
            (await f.CompleteLogin({ payload: { aud: "other-client" } })).Result,
            (await f.CompleteLogin({ mintOpts: { issuer: "https://evil.example/x" } })).Result,
            (await f.CompleteLogin({ mintOpts: { expSecondsFromNow: -120 } })).Result,
        ];
        const reasons = results.map(r => f.Reason(r));
        assert.equal(new Set(reasons).size, 1);
    });

    test("confidential client sends secret by reference and never leaks it", async () =>
    {
        const f = await Fixture.Create(Fixture.SecretRef);
        const { Result } = await f.CompleteLogin();
        assert.ok(Result instanceof AuthenticatedResult);
        const last = f.Http.PostedFields[f.Http.PostedFields.length - 1]!;
        assert.equal(last.get("client_secret"), Fixture.SecretValue);
        for (const text of [String(Result), JSON.stringify(Result)])
        {
            assert.ok(!text.includes(Fixture.SecretValue));
            assert.ok(!text.includes(Fixture.DefaultCode));
        }
    });
});
