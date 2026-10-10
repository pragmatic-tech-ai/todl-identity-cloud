import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
    AccessContext,
    Action,
    Principal,
    PrincipalKind,
    ResourceKind,
    ResourceRef,
    Role,
    Tenant,
    TenantKind,
} from "@pragmatic-tech-ai/todl-identity";
import { ClaimsAccessPolicy } from "../claims-access-policy.js";

class Fixture
{
    public readonly Policy = new ClaimsAccessPolicy(new Map([["admins", Role.Admin], ["viewers", Role.Viewer]]));
    public readonly Resource = new ResourceRef(ResourceKind.Model, "t1", []);

    public ContextFor(groups: string[]): AccessContext
    {
        const principal = new Principal("p1", "t1", PrincipalKind.User, new Map(), groups);
        return new AccessContext(principal, new Tenant("t1", TenantKind.Saas, "T1"), [], this.Policy);
    }
}

describe("ClaimsAccessPolicy", () =>
{
    test("admin group may write and delete", () =>
    {
        const f = new Fixture();
        const ctx = f.ContextFor(["admins"]);
        assert.equal(f.Policy.Decide(ctx, Action.Write, f.Resource).Allowed, true);
        assert.equal(f.Policy.Decide(ctx, Action.Delete, f.Resource).Allowed, true);
    });

    test("viewer group may read but not write", () =>
    {
        const f = new Fixture();
        const ctx = f.ContextFor(["viewers"]);
        assert.equal(f.Policy.Decide(ctx, Action.Read, f.Resource).Allowed, true);
        assert.equal(f.Policy.Decide(ctx, Action.Write, f.Resource).Allowed, false);
    });

    test("no groups and unmapped groups are denied", () =>
    {
        const f = new Fixture();
        assert.equal(f.Policy.Decide(f.ContextFor([]), Action.Read, f.Resource).Allowed, false);
        assert.equal(f.Policy.Decide(f.ContextFor(["other"]), Action.Read, f.Resource).Allowed, false);
    });

    test("entity filter is allow-all", () =>
    {
        const f = new Fixture();
        const filter = f.Policy.EntityFilterFor(f.ContextFor(["viewers"]), Action.Read, "Account");
        assert.equal(filter.Matches({} as never), true);
    });
});
