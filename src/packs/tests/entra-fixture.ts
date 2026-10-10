import { DelegationDepth, IdentityConfig, Tenant, TenantKind } from "@pragmatic-tech-ai/todl-identity";
import type { ISecretStore, Role } from "@pragmatic-tech-ai/todl-identity";
import { FakeAuditSink, FakeRoleGrantStore, FakeSessionManager } from "@pragmatic-tech-ai/todl-identity/testing";
import { MicrosoftEntraPack } from "../microsoft-entra-pack.js";
import { OidcSettingKeys } from "../../pack/oidc-setting-keys.js";
import { InMemoryOidcFlowStateStore } from "../../oidc/flow-state-store.js";
import { FakeOidcHttpClient, FakeOidcIdp } from "../../testing/fake-oidc-idp.js";

export class MapSecretStore implements ISecretStore
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

export class EntraFixture
{
    public static readonly EntraIssuer = "https://login.microsoftonline.com/test-tid/v2.0";
    public static readonly AadTenant = "test-tid";
    public static readonly ClientId = "client-1";
    public static readonly RedirectUri = "https://app.test/cb";
    public static readonly ConfigPackId = "entra";
    public static readonly TenantId = "t1";
    public static readonly TenantName = "Acme";
    public static readonly Subject = "u1";
    public static readonly Email = "a@x.io";
    public static readonly Group = "group-ed";
    public static readonly AuthCode = "auth-code";
    public static readonly BearerType = "Bearer";

    public static Settings(): Map<string, string>
    {
        return new Map([
            [OidcSettingKeys.AadTenantId, EntraFixture.AadTenant],
            [OidcSettingKeys.ClientId, EntraFixture.ClientId],
            [OidcSettingKeys.RedirectUri, EntraFixture.RedirectUri],
        ]);
    }

    public static Tenant(): Tenant
    {
        return new Tenant(EntraFixture.TenantId, TenantKind.Saas, EntraFixture.TenantName);
    }

    public static async EntraFlow(
        depth: DelegationDepth = DelegationDepth.AuthnDirectory,
        groupRoleMap: ReadonlyMap<string, Role> = new Map())
    {
        const idp = await FakeOidcIdp.Create(EntraFixture.EntraIssuer);
        const http = new FakeOidcHttpClient(idp);
        const sessions = new FakeSessionManager();
        const grants = new FakeRoleGrantStore();
        const audit = new FakeAuditSink();
        const flowStates = new InMemoryOidcFlowStateStore();
        const config = new IdentityConfig(EntraFixture.ConfigPackId, depth, EntraFixture.Settings(), groupRoleMap, new Map());
        const pack = MicrosoftEntraPack.Create({
            Config: config,
            Http: http,
            FlowStates: flowStates,
            Secrets: new MapSecretStore(),
            Sessions: sessions,
            Grants: grants,
            Audit: audit,
        });
        const tenant = EntraFixture.Tenant();
        const { State } = await pack.BeginAuthorization(tenant);
        const nonce = flowStates.Peek(State)!.Nonce;
        const idToken = await idp.MintIdToken({
            sub: EntraFixture.Subject,
            aud: EntraFixture.ClientId,
            nonce,
            email: EntraFixture.Email,
            groups: [EntraFixture.Group],
        });
        http.NextTokenResponse = { id_token: idToken, token_type: EntraFixture.BearerType };
        return { pack, tenant, http, audit, sessions, grants, State, idp, idToken };
    }
}
