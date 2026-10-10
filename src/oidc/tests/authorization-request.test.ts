import { test } from "node:test";
import assert from "node:assert/strict";
import { AuthorizationRequest } from "../authorization-request.js";

test("Build emits the full authorization-code + PKCE query", () =>
{
    const built = AuthorizationRequest.Build({
        AuthorizationEndpoint: "https://idp.example/authorize",
        ClientId: "client-1",
        RedirectUri: "https://app.example/cb?x=1",
        Scopes: ["openid", "profile", "email"],
        State: "st",
        Nonce: "no",
        Challenge: "ch"
    });
    const url = new URL(built);
    const q = url.searchParams;
    assert.equal(url.origin + url.pathname, "https://idp.example/authorize");
    assert.equal(q.get("response_type"), "code");
    assert.equal(q.get("code_challenge_method"), "S256");
    assert.equal(q.get("state"), "st");
    assert.equal(q.get("nonce"), "no");
    assert.equal(q.get("code_challenge"), "ch");
    assert.equal(q.get("client_id"), "client-1");
    assert.equal(q.get("redirect_uri"), "https://app.example/cb?x=1");
    assert.equal(q.get("scope"), "openid profile email");
});
