import { test } from "node:test";
import assert from "node:assert/strict";
import {
    PerUserSourceTokenCache,
    SourceTokenError,
    SourceTokenFailure,
    SourceTokenRequest,
} from "@pragmatic-tech-ai/todl-identity";
import { MapSecretStore } from "../../packs/tests/entra-fixture.js";
import type { IHttpClient } from "../../http/http-client.js";
import { OidcDiscovery } from "../../oidc/oidc-discovery.js";
import { OidcResolvedConfig } from "../../oidc/oidc-resolved-config.js";
import { FakeOidcHttpClient, FakeOidcIdp } from "../../testing/fake-oidc-idp.js";
import { OnBehalfOfTokenProvider } from "../on-behalf-of-token-provider.js";
import { UpstreamTokens, UpstreamTokenVault } from "../upstream-token-vault.js";

class OboHttp implements IHttpClient
{
    public readonly Posts: Array<ReadonlyMap<string, string>> = [];

    public constructor(private readonly inner: FakeOidcHttpClient, private readonly mint: (fields: ReadonlyMap<string, string>) => unknown)
    {
    }

    public GetJson(url: string, bearer?: string): Promise<unknown>
    {
        return this.inner.GetJson(url, bearer);
    }

    public async PostForm(_url: string, fields: ReadonlyMap<string, string>): Promise<unknown>
    {
        this.Posts.push(fields);
        return this.mint(fields);
    }
}

class Fixture
{
    public static readonly Tenant = "t1";
    public static readonly Resource = "api://downstream/.default";
    public static readonly ApiScope = "api://app/access";
    public static readonly SecretRef = "obo-secret-ref";
    public static readonly ClientSecret = "obo-client-secret";
    public static readonly ExchangeExp = 4_000_000_000;

    public readonly Vault: UpstreamTokenVault;
    public readonly Cache = new PerUserSourceTokenCache();
    public Provider!: OnBehalfOfTokenProvider;
    public Http!: OboHttp;

    private constructor(private readonly idp: FakeOidcIdp, private readonly secrets: MapSecretStore)
    {
        this.Vault = new UpstreamTokenVault(secrets);
    }

    public static async Create(now: Date = new Date()): Promise<Fixture>
    {
        const idp = await FakeOidcIdp.Create();
        const secrets = new MapSecretStore();
        await secrets.Put(Fixture.SecretRef, Fixture.ClientSecret);
        const fixture = new Fixture(idp, secrets);
        fixture.Http = new OboHttp(new FakeOidcHttpClient(idp), (fields) => fixture.Mint(fields));
        fixture.Provider = new OnBehalfOfTokenProvider({
            Http: fixture.Http,
            Discovery: new OidcDiscovery(fixture.Http, () => now),
            Resolved: new OidcResolvedConfig(idp.DiscoveryUrl, idp.Issuer, "client-1", "https://app.test/cb", ["openid"], Fixture.SecretRef, "client_secret"),
            Secrets: secrets,
            Vault: fixture.Vault,
            ApiScope: Fixture.ApiScope,
            Cache: fixture.Cache,
            now: () => now,
        });
        return fixture;
    }

    public static Unsigned(claims: Record<string, unknown>): string
    {
        const encode = (v: object): string => Buffer.from(JSON.stringify(v)).toString("base64url");
        return encode({ alg: "none", typ: "JWT" }) + "." + encode(claims) + ".";
    }

    public static Request(principal: string): SourceTokenRequest
    {
        return new SourceTokenRequest(Fixture.Tenant, principal, Fixture.Resource);
    }

    private Mint(fields: ReadonlyMap<string, string>): unknown
    {
        if (fields.get("grant_type") === "refresh_token")
        {
            return { access_token: Fixture.Unsigned({ exp: Fixture.ExchangeExp, who: "refreshed" }), refresh_token: "rt-2" };
        }
        return { access_token: Fixture.Unsigned({ exp: Fixture.ExchangeExp, for: fields.get("assertion") }) };
    }
}

class Cases
{
    public static Register(): void
    {
        test("obo exchanges the stored assertion for the requested resource", async () =>
        {
            const f = await Fixture.Create();
            const assertion = Fixture.Unsigned({ exp: 4_100_000_000, who: "alice" });
            await f.Vault.Put(Fixture.Tenant, "alice", new UpstreamTokens(assertion, "rt"));
            const token = await f.Provider.Acquire(Fixture.Request("alice"));
            assert.equal(f.Http.Posts.length, 1);
            const post = f.Http.Posts[0];
            assert.equal(post.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
            assert.equal(post.get("client_id"), "client-1");
            assert.equal(post.get("client_secret"), Fixture.ClientSecret);
            assert.equal(post.get("assertion"), assertion);
            assert.equal(post.get("scope"), Fixture.Resource);
            assert.equal(post.get("requested_token_use"), "on_behalf_of");
            assert.equal(token.Value.Reveal(), Fixture.Unsigned({ exp: Fixture.ExchangeExp, for: assertion }));
            assert.equal(token.ExpiresAt.getTime(), Fixture.ExchangeExp * 1000);
        });

        test("obo refreshes an expired assertion first", async () =>
        {
            const now = new Date();
            const f = await Fixture.Create(now);
            const expired = Fixture.Unsigned({ exp: Math.floor(now.getTime() / 1000) - 10 });
            await f.Vault.Put(Fixture.Tenant, "alice", new UpstreamTokens(expired, "rt-1"));
            await f.Provider.Acquire(Fixture.Request("alice"));
            assert.equal(f.Http.Posts.length, 2);
            assert.equal(f.Http.Posts[0].get("grant_type"), "refresh_token");
            assert.equal(f.Http.Posts[0].get("refresh_token"), "rt-1");
            assert.equal(f.Http.Posts[0].get("scope"), Fixture.ApiScope);
            assert.equal(f.Http.Posts[1].get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
            const stored = await f.Vault.Get(Fixture.Tenant, "alice");
            assert.equal(f.Http.Posts[1].get("assertion"), stored?.AccessToken);
            assert.equal(stored?.RefreshToken, "rt-2");
        });

        test("missing upstream session rejects and never falls back", async () =>
        {
            const f = await Fixture.Create();
            await assert.rejects(
                f.Provider.Acquire(Fixture.Request("nobody")),
                (e: unknown) => e instanceof SourceTokenError && e.Failure === SourceTokenFailure.NoUpstreamSession);
            assert.equal(f.Http.Posts.length, 0);
        });

        test("obo rejects an expired assertion with no refresh token and makes no POST", async () =>
        {
            const now = new Date();
            const f = await Fixture.Create(now);
            const expired = Fixture.Unsigned({ exp: Math.floor(now.getTime() / 1000) - 10 });
            await f.Vault.Put(Fixture.Tenant, "alice", new UpstreamTokens(expired, null));
            await assert.rejects(
                f.Provider.Acquire(Fixture.Request("alice")),
                (e: unknown) => e instanceof SourceTokenError && e.Failure === SourceTokenFailure.NoUpstreamSession);
            assert.equal(f.Http.Posts.length, 0);
        });

        test("obo never serves alice's token to bob", async () =>
        {
            const f = await Fixture.Create();
            const aliceAssertion = Fixture.Unsigned({ exp: 4_100_000_000, who: "alice" });
            const bobAssertion = Fixture.Unsigned({ exp: 4_100_000_000, who: "bob" });
            await f.Vault.Put(Fixture.Tenant, "alice", new UpstreamTokens(aliceAssertion, null));
            await f.Vault.Put(Fixture.Tenant, "bob", new UpstreamTokens(bobAssertion, null));
            const alice = await f.Provider.Acquire(Fixture.Request("alice"));
            const bob = await f.Provider.Acquire(Fixture.Request("bob"));
            assert.notEqual(alice.Value.Reveal(), bob.Value.Reveal());
            assert.equal(f.Http.Posts.length, 2);
            assert.equal((await f.Provider.Acquire(Fixture.Request("alice"))).Value.Reveal(), alice.Value.Reveal());
            assert.equal(f.Http.Posts.length, 2);
            assert.ok(f.Cache.Get(Fixture.Request("alice"), new Date()));
            assert.ok(f.Cache.Get(Fixture.Request("bob"), new Date()));
        });
    }
}

Cases.Register();
