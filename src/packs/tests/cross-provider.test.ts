import { test } from "node:test";
import assert from "node:assert/strict";
import type { AuthenticationResult } from "@pragmatic-tech-ai/todl-identity";
import { AuthMethod, AuthenticatedResult, Credential, DelegationDepth, IdentityConfig, PresentedSecret, RejectedResult, Tenant, TenantKind } from "@pragmatic-tech-ai/todl-identity";
import { FakeAuditSink, FakeRoleGrantStore, FakeSessionManager } from "@pragmatic-tech-ai/todl-identity/testing";
import { MicrosoftEntraProfile } from "../microsoft-entra-profile.js";
import { GoogleIdentityProfile } from "../google-identity-profile.js";
import { MicrosoftEntraPack } from "../microsoft-entra-pack.js";
import { GoogleIdentityPack } from "../google-identity-pack.js";
import { OidcSettingKeys } from "../../pack/oidc-setting-keys.js";
import { InMemoryOidcFlowStateStore } from "../../oidc/flow-state-store.js";
import { FakeOidcHttpClient, FakeOidcIdp } from "../../testing/fake-oidc-idp.js";
import { MapSecretStore } from "./entra-fixture.js";

class Fixture
{
    public static readonly GoogleIssuer = GoogleIdentityProfile.GoogleIssuer;
    public static readonly TenantIdValue = "test-tid";
    public static readonly EntraIssuer = new MicrosoftEntraProfile().ResolveIssuer(new Map([[OidcSettingKeys.AadTenantId, Fixture.TenantIdValue]]));
    public static readonly ClientId = "client-1";
    public static readonly RedirectUri = "https://app.test/cb";
    public static readonly EntraPackId = "entra";
    public static readonly GooglePackId = "google";
    public static readonly Subject = "u1";
    public static readonly AuthCode = "code";
    public static readonly TenantRef = "t1";
    public static readonly TenantName = "Acme";
    public static readonly EntraTokenName = "cross-provider: Entra-minted token is rejected by the Google pack";
    public static readonly PositiveControlName = "cross-provider control: a token from the pack own IdP authenticates";
    public static readonly GoogleTokenName = "cross-provider: Google-minted token is rejected by the Entra pack";

    public constructor(
        public readonly IdpA: FakeOidcIdp,
        public readonly HttpA: FakeOidcHttpClient,
        public readonly FlowStatesA: InMemoryOidcFlowStateStore,
        public readonly EntraPack: MicrosoftEntraPack,
        public readonly IdpB: FakeOidcIdp,
        public readonly HttpB: FakeOidcHttpClient,
        public readonly FlowStatesB: InMemoryOidcFlowStateStore,
        public readonly GooglePack: GoogleIdentityPack,
        public readonly TenantValue: Tenant)
    {
    }

    public static async Create(): Promise<Fixture>
    {
        const idpA = await FakeOidcIdp.Create(Fixture.EntraIssuer);
        const httpA = new FakeOidcHttpClient(idpA);
        const flowStatesA = new InMemoryOidcFlowStateStore();
        const entraSettings = new Map([
            [OidcSettingKeys.AadTenantId, Fixture.TenantIdValue],
            [OidcSettingKeys.ClientId, Fixture.ClientId],
            [OidcSettingKeys.RedirectUri, Fixture.RedirectUri],
        ]);
        const entraPack = MicrosoftEntraPack.Create({
            Config: new IdentityConfig(Fixture.EntraPackId, DelegationDepth.ExternalGrants, entraSettings, new Map(), new Map()),
            Http: httpA,
            FlowStates: flowStatesA,
            Secrets: new MapSecretStore(),
            Sessions: new FakeSessionManager(),
            Grants: new FakeRoleGrantStore(),
            Audit: new FakeAuditSink(),
        });
        const idpB = await FakeOidcIdp.Create(Fixture.GoogleIssuer);
        const httpB = new FakeOidcHttpClient(idpB);
        const flowStatesB = new InMemoryOidcFlowStateStore();
        const googleSettings = new Map([
            [OidcSettingKeys.ClientId, Fixture.ClientId],
            [OidcSettingKeys.RedirectUri, Fixture.RedirectUri],
        ]);
        const googlePack = GoogleIdentityPack.Create({
            Config: new IdentityConfig(Fixture.GooglePackId, DelegationDepth.ExternalGrants, googleSettings, new Map(), new Map()),
            Http: httpB,
            FlowStates: flowStatesB,
            Secrets: new MapSecretStore(),
            Sessions: new FakeSessionManager(),
            Grants: new FakeRoleGrantStore(),
            Audit: new FakeAuditSink(),
        });
        const tenant = new Tenant(Fixture.TenantRef, TenantKind.Saas, Fixture.TenantName);
        return new Fixture(idpA, httpA, flowStatesA, entraPack, idpB, httpB, flowStatesB, googlePack, tenant);
    }

    /** Begins a real authorization on the pack (valid state + nonce), then answers with a token minted by the foreign IdP. */
    public async Attempt(
        pack: MicrosoftEntraPack | GoogleIdentityPack,
        flowStates: InMemoryOidcFlowStateStore,
        http: FakeOidcHttpClient,
        foreignIdp: FakeOidcIdp): Promise<AuthenticationResult>
    {
        const { State } = await pack.BeginAuthorization(this.TenantValue);
        const nonce = flowStates.Peek(State)!.Nonce;
        http.NextTokenResponse = { id_token: await foreignIdp.MintIdToken({ sub: Fixture.Subject, aud: Fixture.ClientId, nonce }) };
        return await pack.AuthenticatorFor(AuthMethod.Oidc)!.Authenticate(
            new Credential(AuthMethod.Oidc, State),
            new PresentedSecret(Fixture.AuthCode),
            this.TenantValue);
    }
}

class CrossProviderTests
{
    public static Register(): void
    {
        test(Fixture.PositiveControlName, async () =>
        {
            const fx = await Fixture.Create();
            const google = await fx.Attempt(fx.GooglePack, fx.FlowStatesB, fx.HttpB, fx.IdpB);
            assert.ok(google instanceof AuthenticatedResult);
            assert.equal((google as AuthenticatedResult).Principal.Id, Fixture.Subject);
            const entra = await fx.Attempt(fx.EntraPack, fx.FlowStatesA, fx.HttpA, fx.IdpA);
            assert.ok(entra instanceof AuthenticatedResult);
            assert.equal((entra as AuthenticatedResult).Principal.Id, Fixture.Subject);
        });

        test(Fixture.EntraTokenName, async () =>
        {
            const fx = await Fixture.Create();
            const result = await fx.Attempt(fx.GooglePack, fx.FlowStatesB, fx.HttpB, fx.IdpA);
            assert.ok(result instanceof RejectedResult);
        });

        test(Fixture.GoogleTokenName, async () =>
        {
            const fx = await Fixture.Create();
            const result = await fx.Attempt(fx.EntraPack, fx.FlowStatesA, fx.HttpA, fx.IdpB);
            assert.ok(result instanceof RejectedResult);
        });
    }
}

CrossProviderTests.Register();
