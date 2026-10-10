import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
    AuthMethod,
    DelegationDepth,
    IdentityConfig,
    Principal,
    PrincipalKind,
    Role,
} from "@pragmatic-tech-ai/todl-identity";
import type { ISecretStore } from "@pragmatic-tech-ai/todl-identity";
import { FakeAuditSink, FakeRoleGrantStore, FakeSessionManager } from "@pragmatic-tech-ai/todl-identity/testing";
import { OidcIdentityProviderPackBase } from "../oidc-identity-provider-pack-base.js";
import { OidcProviderProfile } from "../oidc-provider-profile.js";
import { OidcSettingKeys } from "../oidc-setting-keys.js";
import { ClaimsAccessPolicy } from "../claims-access-policy.js";
import { ClaimArrayGroupStrategy } from "../../claims/group-strategy.js";
import { InMemoryOidcFlowStateStore } from "../../oidc/flow-state-store.js";
import { FakeOidcIdp, FakeOidcHttpClient } from "../../testing/fake-oidc-idp.js";

class MapSecretStore implements ISecretStore
{
    private readonly map = new Map<string, string>();

    public async Get(reference: string): Promise<string | null>
    {
        return this.map.get(reference) ?? null;
    }

    public async Put(reference: string, secret: string): Promise<void>
    {
        this.map.set(reference, secret);
    }

    public async Delete(reference: string): Promise<void>
    {
        this.map.delete(reference);
    }
}

class TestOidcPack extends OidcIdentityProviderPackBase
{
}

class Fixture
{
    private readonly profile = new OidcProviderProfile(
        ["openid"],
        new Map([["email", "email"]]),
        new ClaimArrayGroupStrategy("groups"),
        "client_secret");

    private constructor(private readonly idp: FakeOidcIdp)
    {
    }

    public static async Create(): Promise<Fixture>
    {
        return new Fixture(await FakeOidcIdp.Create());
    }

    public MakePack(depth: DelegationDepth, settings?: Map<string, string>): TestOidcPack
    {
        const providerSettings = settings ?? new Map([
            [OidcSettingKeys.ClientId, "c1"],
            [OidcSettingKeys.RedirectUri, "https://app/cb"],
            [OidcSettingKeys.Issuer, this.idp.Issuer],
            [OidcSettingKeys.DiscoveryUrl, this.idp.DiscoveryUrl],
        ]);
        return new TestOidcPack({
            Profile: this.profile,
            Config: new IdentityConfig("test", depth, providerSettings, new Map([["admins", Role.Admin]]), new Map()),
            Http: new FakeOidcHttpClient(this.idp),
            FlowStates: new InMemoryOidcFlowStateStore(),
            Secrets: new MapSecretStore(),
            Sessions: new FakeSessionManager(),
            Grants: new FakeRoleGrantStore(),
            Audit: new FakeAuditSink(),
        });
    }
}

describe("OidcIdentityProviderPackBase depths", () =>
{
    test("Policy is present only at FullAuthz", async () =>
    {
        const f = await Fixture.Create();
        assert.equal(f.MakePack(DelegationDepth.AuthnDirectory).Policy, undefined);
        assert.equal(f.MakePack(DelegationDepth.ExternalGrants).Policy, undefined);
        assert.ok(f.MakePack(DelegationDepth.FullAuthz).Policy instanceof ClaimsAccessPolicy);
    });

    test("exposes the OIDC authenticator", async () =>
    {
        const f = await Fixture.Create();
        const pack = f.MakePack(DelegationDepth.AuthnDirectory);
        assert.equal(pack.AuthenticatorFor(AuthMethod.Oidc), pack.Authenticators[0]);
        assert.equal(pack.Authenticators[0]?.Method, AuthMethod.Oidc);
        assert.equal(pack.AuthenticatorFor(AuthMethod.Local), undefined);
    });

    test("sessions round-trip through the injected manager", async () =>
    {
        const f = await Fixture.Create();
        const pack = f.MakePack(DelegationDepth.AuthnDirectory);
        const s = await pack.Sessions.Issue(new Principal("p1", "t1", PrincipalKind.User, new Map(), []));
        assert.ok(await pack.Sessions.Validate(s.Id));
    });

    test("a missing required setting throws", async () =>
    {
        const f = await Fixture.Create();
        assert.throws(() => f.MakePack(DelegationDepth.AuthnDirectory, new Map([[OidcSettingKeys.Issuer, "https://x"], [OidcSettingKeys.DiscoveryUrl, "https://x/d"]])));
    });
});
