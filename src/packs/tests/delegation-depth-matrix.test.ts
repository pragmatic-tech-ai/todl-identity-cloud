import { test } from "node:test";
import assert from "node:assert/strict";
import {
    AccessContext,
    Action,
    AuthMethod,
    AuthenticatedResult,
    Credential,
    DelegationDepth,
    Principal,
    PrincipalKind,
    PresentedSecret,
    ResourceKind,
    ResourceRef,
    Role,
} from "@pragmatic-tech-ai/todl-identity";
import type { IAccessPolicy, Tenant } from "@pragmatic-tech-ai/todl-identity";
import { ClaimsAccessPolicy } from "../../pack/claims-access-policy.js";
import { EntraFixture } from "./entra-fixture.js";

type Flow = Awaited<ReturnType<typeof EntraFixture.EntraFlow>>;

class Matrix
{
    private static readonly AdminGroup = "admins";
    private static readonly Concept = "Account";
    private static readonly AuthnName = "AuthnDirectory ignores token groups and exposes no policy";
    private static readonly ExternalName = "ExternalGrants maps token groups to stored grants";
    private static readonly FullName = "FullAuthz exposes a claims policy that decides by group role";

    public static Register(): void
    {
        test(Matrix.AuthnName, async () =>
        {
            const flow = await EntraFixture.EntraFlow(DelegationDepth.AuthnDirectory);
            await Matrix.Authenticate(flow);
            assert.equal((await flow.pack.Grants.GrantsFor(EntraFixture.Subject, flow.tenant)).length, 0);
            assert.equal(flow.pack.Policy, undefined);
        });

        test(Matrix.ExternalName, async () =>
        {
            const flow = await EntraFixture.EntraFlow(DelegationDepth.ExternalGrants, new Map([[EntraFixture.Group, Role.Editor]]));
            await Matrix.Authenticate(flow);
            const grants = await flow.pack.Grants.GrantsFor(EntraFixture.Subject, flow.tenant);
            assert.ok(grants.some((g) => g.Role === Role.Editor));
            assert.equal(flow.pack.Policy, undefined);
        });

        test(Matrix.FullName, async () =>
        {
            const flow = await EntraFixture.EntraFlow(DelegationDepth.FullAuthz, new Map([[Matrix.AdminGroup, Role.Admin]]));
            const policy = flow.pack.Policy!;
            assert.ok(policy instanceof ClaimsAccessPolicy);
            const resource = new ResourceRef(ResourceKind.Model, EntraFixture.TenantId, []);
            const admin = Matrix.Context(flow.tenant, [Matrix.AdminGroup], policy);
            assert.equal(policy.Decide(admin, Action.Write, resource).Allowed, true);
            const nobody = Matrix.Context(flow.tenant, [], policy);
            assert.equal(policy.Decide(nobody, Action.Read, resource).Allowed, false);
            assert.equal(policy.EntityFilterFor(admin, Action.Read, Matrix.Concept).Matches({} as never), true);
        });
    }

    private static async Authenticate(flow: Flow): Promise<void>
    {
        const result = await flow.pack.AuthenticatorFor(AuthMethod.Oidc)!.Authenticate(
            new Credential(AuthMethod.Oidc, flow.State),
            new PresentedSecret(EntraFixture.AuthCode),
            flow.tenant);
        assert.ok(result instanceof AuthenticatedResult);
    }

    private static Context(tenant: Tenant, groups: string[], policy: IAccessPolicy): AccessContext
    {
        const principal = new Principal(EntraFixture.Subject, EntraFixture.TenantId, PrincipalKind.User, new Map(), groups);
        return new AccessContext(principal, tenant, [], policy);
    }
}

Matrix.Register();
