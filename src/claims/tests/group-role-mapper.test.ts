import { test } from "node:test";
import assert from "node:assert/strict";
import { Principal, PrincipalKind, ResourceKind, Role, Tenant, TenantKind } from "@pragmatic-tech-ai/todl-identity";
import { FakeRoleGrantStore } from "@pragmatic-tech-ai/todl-identity/testing";
import { GroupRoleMapper } from "../group-role-mapper.js";

const tenant = new Tenant("t1", TenantKind.Saas, "Acme");

test("maps a group to a tenant-scoped grant", async () =>
{
    const store = new FakeRoleGrantStore();
    const principal = new Principal("u1", "t1", PrincipalKind.User, new Map(), ["admins"]);
    await new GroupRoleMapper(store).ApplyGroups(principal, tenant, new Map([["admins", Role.Admin]]));
    const grants = await store.GrantsFor("u1", tenant);
    assert.equal(grants.length, 1);
    assert.equal(grants[0].Role, Role.Admin);
    assert.equal(grants[0].Resource.Kind, ResourceKind.Tenant);
    assert.equal(grants[0].Resource.TenantId, "t1");
});

test("unmapped group saves nothing", async () =>
{
    const store = new FakeRoleGrantStore();
    const principal = new Principal("u1", "t1", PrincipalKind.User, new Map(), ["other"]);
    await new GroupRoleMapper(store).ApplyGroups(principal, tenant, new Map([["admins", Role.Admin]]));
    assert.equal((await store.GrantsFor("u1", tenant)).length, 0);
});
