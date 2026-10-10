import { DelegationDepth, IdentityConfig } from "@pragmatic-tech-ai/todl-identity";
import type { IIdentityProviderPack } from "@pragmatic-tech-ai/todl-identity";
import {
    FakeAuditSink,
    FakeRoleGrantStore,
    FakeSessionManager,
    IdentityPackConformance,
} from "@pragmatic-tech-ai/todl-identity/testing";
import type { IHttpClient } from "../../http/http-client.js";
import { InMemoryOidcFlowStateStore } from "../../oidc/flow-state-store.js";
import { GoogleIdentityPack } from "../google-identity-pack.js";
import { MapSecretStore } from "./entra-fixture.js";
import { GoogleFixture } from "./google-fixture.js";

class StubHttp implements IHttpClient
{
    private static readonly NoNetwork = "no network in conformance";

    public async GetJson(_url: string): Promise<unknown>
    {
        throw new Error(StubHttp.NoNetwork);
    }

    public async PostForm(_url: string, _fields: ReadonlyMap<string, string>): Promise<unknown>
    {
        throw new Error(StubHttp.NoNetwork);
    }
}

class ConformanceFixture
{
    private static readonly Label = "GoogleIdentityPack";

    public static Register(): void
    {
        IdentityPackConformance.Describe(ConformanceFixture.Label, () => ConformanceFixture.ConformancePack());
    }

    private static ConformancePack(): IIdentityProviderPack
    {
        return GoogleIdentityPack.Create({
            Config: new IdentityConfig(
                GoogleFixture.ConfigPackId,
                DelegationDepth.AuthnDirectory,
                GoogleFixture.Settings(),
                new Map(),
                new Map()),
            Http: new StubHttp(),
            FlowStates: new InMemoryOidcFlowStateStore(),
            Secrets: new MapSecretStore(),
            Sessions: new FakeSessionManager(),
            Grants: new FakeRoleGrantStore(),
            Audit: new FakeAuditSink(),
        });
    }
}

ConformanceFixture.Register();
