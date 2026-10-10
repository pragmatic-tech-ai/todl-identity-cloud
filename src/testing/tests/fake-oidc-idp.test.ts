import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeOidcIdp } from "../fake-oidc-idp.js";

test("FakeOidcIdp serves discovery, JWKS and mints a JWT", async () =>
{
    const idp = await FakeOidcIdp.Create();
    assert.equal((idp.DiscoveryDocument() as { issuer: string }).issuer, idp.Issuer);
    const keys = idp.Jwks().keys;
    assert.equal(keys.length, 1);
    assert.ok(keys[0].kid);
    const token = await idp.MintIdToken({ sub: "u1" });
    assert.equal(token.split(".").length, 3);
});
