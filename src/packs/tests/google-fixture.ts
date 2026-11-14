import { DelegationDepth, IdentityConfig, Realm, RealmKind } from "@pragmatic-tech-ai/todl-identity";
import { FakeAuditSink, FakeRoleGrantStore, FakeSessionManager } from "@pragmatic-tech-ai/todl-identity/testing";
import { GoogleIdentityPack } from "../google-identity-pack.js";
import { GoogleIdentityProfile } from "../google-identity-profile.js";
import { OidcSettingKeys } from "../../pack/oidc-setting-keys.js";
import { InMemoryOidcFlowStateStore } from "../../oidc/flow-state-store.js";
import { FakeOidcHttpClient, FakeOidcIdp } from "../../testing/fake-oidc-idp.js";
import type { MintOptions } from "../../testing/fake-oidc-idp.js";
import { MapSecretStore } from "./entra-fixture.js";

export class GoogleFixture
{
    public static readonly ClientId = "client-1";
    public static readonly RedirectUri = "https://app.test/cb";
    public static readonly ConfigPackId = "google";
    public static readonly RealmId = "t1";
    public static readonly RealmName = "Acme";
    public static readonly AuthCode = "auth-code";
    public static readonly BearerType = "Bearer";
    public static readonly SubHd = "u1";
    public static readonly EmailA = "a@x.io";
    public static readonly SubNoHd = "u2";
    public static readonly EmailB = "b@x.io";
    public static readonly SubEvil = "u3";
    public static readonly EmailC = "c@x.io";

    public static Settings(): Map<string, string>
    {
        return new Map([
            [OidcSettingKeys.ClientId, GoogleFixture.ClientId],
            [OidcSettingKeys.RedirectUri, GoogleFixture.RedirectUri],
        ]);
    }

    public static Realm(): Realm
    {
        return new Realm(GoogleFixture.RealmId, RealmKind.Saas, GoogleFixture.RealmName);
    }

    /** Begins authorization, mints an id_token echoing the nonce plus extra claims, and primes the fake token endpoint. */
    public static async GoogleFlow(
        extraClaims: Record<string, unknown>,
        mint?: MintOptions,
        depth: DelegationDepth = DelegationDepth.ExternalGrants)
    {
        const idp = await FakeOidcIdp.Create(GoogleIdentityProfile.GoogleIssuer);
        const http = new FakeOidcHttpClient(idp);
        const audit = new FakeAuditSink();
        const flowStates = new InMemoryOidcFlowStateStore();
        const config = new IdentityConfig(GoogleFixture.ConfigPackId, depth, GoogleFixture.Settings(), new Map(), new Map());
        const pack = GoogleIdentityPack.Create({
            Config: config,
            Http: http,
            FlowStates: flowStates,
            Secrets: new MapSecretStore(),
            Sessions: new FakeSessionManager(),
            Grants: new FakeRoleGrantStore(),
            Audit: audit,
        });
        const realm = GoogleFixture.Realm();
        const { State } = await pack.BeginAuthorization(realm);
        const nonce = flowStates.Peek(State)!.Nonce;
        const idToken = await idp.MintIdToken({ aud: GoogleFixture.ClientId, nonce, ...extraClaims }, mint);
        http.NextTokenResponse = { id_token: idToken, token_type: GoogleFixture.BearerType };
        return { pack, realm, audit, State, idToken };
    }
}
