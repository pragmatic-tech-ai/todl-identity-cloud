import { test } from "node:test";
import assert from "node:assert/strict";
import type { IHttpClient } from "../../http/http-client.js";
import { FakeOidcIdp, FakeOidcHttpClient } from "../../testing/fake-oidc-idp.js";
import { OidcDiscovery } from "../oidc-discovery.js";

class SpyHttpClient implements IHttpClient
{
    public GetCount = 0;

    public constructor(private readonly inner: IHttpClient)
    {
    }

    public GetJson(url: string): Promise<unknown>
    {
        this.GetCount++;
        return this.inner.GetJson(url);
    }

    public PostForm(url: string, fields: ReadonlyMap<string, string>): Promise<unknown>
    {
        return this.inner.PostForm(url, fields);
    }
}

class StubHttpClient implements IHttpClient
{
    public constructor(private readonly doc: unknown)
    {
    }

    public async GetJson(): Promise<unknown>
    {
        return this.doc;
    }

    public async PostForm(): Promise<unknown>
    {
        return {};
    }
}

test("Endpoints reads the four fields and caches within TTL", async () =>
{
    const idp = await FakeOidcIdp.Create();
    const spy = new SpyHttpClient(new FakeOidcHttpClient(idp));
    const discovery = new OidcDiscovery(spy);
    const e = await discovery.Endpoints(idp.DiscoveryUrl);
    assert.equal(e.Issuer, idp.Issuer);
    assert.equal(e.AuthorizationEndpoint, idp.AuthorizationEndpoint);
    assert.equal(e.TokenEndpoint, idp.TokenEndpoint);
    assert.equal(e.JwksUri, idp.JwksUri);
    await discovery.Endpoints(idp.DiscoveryUrl);
    assert.equal(spy.GetCount, 1);
});

test("Endpoints refetches after TTL expiry", async () =>
{
    const idp = await FakeOidcIdp.Create();
    const spy = new SpyHttpClient(new FakeOidcHttpClient(idp));
    let t = 1_000_000;
    const discovery = new OidcDiscovery(spy, () => new Date(t));
    await discovery.Endpoints(idp.DiscoveryUrl);
    t += 400_000;
    await discovery.Endpoints(idp.DiscoveryUrl);
    assert.equal(spy.GetCount, 2);
});

test("Endpoints rejects a document with missing fields", async () =>
{
    const discovery = new OidcDiscovery(new StubHttpClient({ issuer: "https://x" }));
    await assert.rejects(discovery.Endpoints("https://x/.well-known/openid-configuration"));
});

test("Endpoints rejects a non-https endpoint", async () =>
{
    const doc = {
        issuer: "https://x",
        authorization_endpoint: "https://x/auth",
        token_endpoint: "http://x/token",
        jwks_uri: "https://x/jwks"
    };
    const discovery = new OidcDiscovery(new StubHttpClient(doc));
    await assert.rejects(discovery.Endpoints("https://x/.well-known/openid-configuration"));
});
