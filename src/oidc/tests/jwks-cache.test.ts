import { test } from "node:test";
import assert from "node:assert/strict";
import { jwtVerify } from "jose";
import { FakeOidcIdp, FakeOidcHttpClient } from "../../testing/fake-oidc-idp.js";
import { JwksCache } from "../jwks-cache.js";

test("KeySet validates minted tokens and is cached", async () =>
{
    const idp = await FakeOidcIdp.Create();
    const cache = new JwksCache(new FakeOidcHttpClient(idp));
    const keySet = await cache.KeySet(idp.JwksUri);
    const token = await idp.MintIdToken({ sub: "u1", aud: "client-1", nonce: "n" });
    const { payload } = await jwtVerify(token, keySet, { issuer: idp.Issuer, audience: "client-1" });
    assert.equal(payload.sub, "u1");

    const again = await cache.KeySet(idp.JwksUri);
    assert.equal(again, keySet);
    const token2 = await idp.MintIdToken({ sub: "u2", aud: "client-1", nonce: "n" });
    const second = await jwtVerify(token2, again, { issuer: idp.Issuer, audience: "client-1" });
    assert.equal(second.payload.sub, "u2");
});

test("Refresh builds a new key set", async () =>
{
    const idp = await FakeOidcIdp.Create();
    const cache = new JwksCache(new FakeOidcHttpClient(idp));
    const first = await cache.KeySet(idp.JwksUri);
    const refreshed = await cache.Refresh(idp.JwksUri);
    assert.notEqual(refreshed, first);
});
