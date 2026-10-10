import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { PkceChallenge } from "../pkce-challenge.js";

test("challenge is the S256 of the verifier", () =>
{
    const p = PkceChallenge.Create();
    assert.equal(p.Method, "S256");
    assert.equal(p.Challenge, createHash("sha256").update(p.Verifier).digest("base64url"));
    assert.ok(p.Verifier.length >= 43);
});

test("each Create yields a distinct verifier", () =>
{
    assert.notEqual(PkceChallenge.Create().Verifier, PkceChallenge.Create().Verifier);
});
