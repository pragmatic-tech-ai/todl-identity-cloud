import { test } from "node:test";
import assert from "node:assert/strict";
import { DelegationDepth, IdentityConfig, Tenant, TenantKind } from "@pragmatic-tech-ai/todl-identity";
import { ClaimsMapper } from "../claims-mapper.js";
import { ClaimArrayGroupStrategy } from "../group-strategy.js";

class Fixture
{
    public static readonly Tenant = new Tenant("t1", TenantKind.Saas, "Acme");

    public static Config(mapping: Map<string, string>): IdentityConfig
    {
        return new IdentityConfig("pack", DelegationDepth.AuthnDirectory, new Map(), new Map(), mapping);
    }

    public static Mapper(): ClaimsMapper
    {
        return new ClaimsMapper(new Map([["email", "email"]]), new ClaimArrayGroupStrategy("groups"));
    }
}

test("maps sub, claims and groups", () =>
{
    const p = Fixture.Mapper().Map({ sub: "u1", email: "a@x.io", groups: ["g1", "g2"] }, Fixture.Tenant, Fixture.Config(new Map()));
    assert.equal(p.Id, "u1");
    assert.equal(p.Claim("email"), "a@x.io");
    assert.deepEqual(p.Groups, ["g1", "g2"]);
});

test("per-tenant ClaimsMapping overrides defaults", () =>
{
    const config = Fixture.Config(new Map([["email", "preferred_username"]]));
    const p = Fixture.Mapper().Map({ sub: "u1", email: "a@x.io", preferred_username: "bob@x.io", groups: [] }, Fixture.Tenant, config);
    assert.equal(p.Claim("email"), "bob@x.io");
});

test("non-array groups claim yields no groups", () =>
{
    const p = Fixture.Mapper().Map({ sub: "u1", groups: "nope" }, Fixture.Tenant, Fixture.Config(new Map()));
    assert.deepEqual(p.Groups, []);
});

test("missing or empty sub throws", () =>
{
    const config = Fixture.Config(new Map());
    assert.throws(() => Fixture.Mapper().Map({ email: "a@x.io" }, Fixture.Tenant, config));
    assert.throws(() => Fixture.Mapper().Map({ sub: "" }, Fixture.Tenant, config));
});

test("structured and null claim values are skipped, scalars coerced", () =>
{
    const mapper = new ClaimsMapper(
        new Map([["email", "email"], ["role", "role"], ["age", "age"], ["admin", "admin"], ["nick", "nick"]]),
        new ClaimArrayGroupStrategy("groups"));
    const p = mapper.Map({ sub: "u1", email: { a: 1 }, role: ["x"], age: 42, admin: true, nick: null }, Fixture.Tenant, Fixture.Config(new Map()));
    assert.equal(p.Claim("email"), undefined);
    assert.equal(p.Claim("role"), undefined);
    assert.equal(p.Claim("nick"), undefined);
    assert.equal(p.Claim("age"), "42");
    assert.equal(p.Claim("admin"), "true");
});
