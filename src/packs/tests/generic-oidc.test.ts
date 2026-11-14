import { test } from "node:test";
import assert from "node:assert/strict";
import { AuthMethod, AuthenticatedResult, Credential, DelegationDepth, IdentityConfig, PresentedSecret, Realm, RealmKind } from "@pragmatic-tech-ai/todl-identity";
import { FakeAuditSink, FakeRoleGrantStore, FakeSessionManager } from "@pragmatic-tech-ai/todl-identity/testing";
import { GenericOidcPack } from "../generic-oidc-pack.js";
import { GenericOidcProfile } from "../generic-oidc-profile.js";
import { ClaimArrayGroupStrategy } from "../../claims/group-strategy.js";
import { OidcSettingKeys } from "../../pack/oidc-setting-keys.js";
import { InMemoryOidcFlowStateStore } from "../../oidc/flow-state-store.js";
import { FakeOidcHttpClient, FakeOidcIdp } from "../../testing/fake-oidc-idp.js";
import { MapSecretStore } from "./entra-fixture.js";

class Fixture
{
    public static readonly ClientId = "client-1";
    public static readonly RedirectUri = "https://app.test/cb";
    public static readonly PackId = "generic";
    public static readonly OpenIdScope = "openid";
    public static readonly EmailClaim = "email";
    public static readonly RolesClaim = "roles";
    public static readonly Subject = "u1";
    public static readonly Email = "a@x.io";
    public static readonly Role = "r1";
    public static readonly AuthCode = "code";
    public static readonly RealmRef = "t1";
    public static readonly RealmName = "Acme";
    public static readonly GoldenName = "generic OIDC: a profile-only provider authenticates and maps groups from the roles claim";
}

class GenericOidcTests
{
    public static Register(): void
    {
        test(Fixture.GoldenName, async () =>
        {
            const idp = await FakeOidcIdp.Create();
            const http = new FakeOidcHttpClient(idp);
            const flowStates = new InMemoryOidcFlowStateStore();
            const profile = new GenericOidcProfile(
                idp.Issuer,
                idp.DiscoveryUrl,
                [Fixture.OpenIdScope],
                new Map([[Fixture.EmailClaim, Fixture.EmailClaim]]),
                new ClaimArrayGroupStrategy(Fixture.RolesClaim));
            const settings = new Map([
                [OidcSettingKeys.ClientId, Fixture.ClientId],
                [OidcSettingKeys.RedirectUri, Fixture.RedirectUri],
            ]);
            const pack = GenericOidcPack.Create({
                Profile: profile,
                Config: new IdentityConfig(Fixture.PackId, DelegationDepth.ExternalGrants, settings, new Map(), new Map()),
                Http: http,
                FlowStates: flowStates,
                Secrets: new MapSecretStore(),
                Sessions: new FakeSessionManager(),
                Grants: new FakeRoleGrantStore(),
                Audit: new FakeAuditSink(),
            });
            const realm = new Realm(Fixture.RealmRef, RealmKind.Saas, Fixture.RealmName);
            const { State } = await pack.BeginAuthorization(realm);
            const nonce = flowStates.Peek(State)!.Nonce;
            http.NextTokenResponse = {
                id_token: await idp.MintIdToken({
                    sub: Fixture.Subject,
                    aud: Fixture.ClientId,
                    nonce,
                    [Fixture.EmailClaim]: Fixture.Email,
                    [Fixture.RolesClaim]: [Fixture.Role],
                }),
            };
            const result = await pack.AuthenticatorFor(AuthMethod.Oidc)!.Authenticate(
                new Credential(AuthMethod.Oidc, State),
                new PresentedSecret(Fixture.AuthCode),
                realm);
            assert.ok(result instanceof AuthenticatedResult);
            const principal = (result as AuthenticatedResult).Principal;
            assert.equal(principal.Id, Fixture.Subject);
            assert.equal(principal.Claim(Fixture.EmailClaim), Fixture.Email);
            assert.deepEqual([...principal.Groups], [Fixture.Role]);
        });
    }
}

GenericOidcTests.Register();
