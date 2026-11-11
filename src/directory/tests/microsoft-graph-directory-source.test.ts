import { test } from "node:test";
import assert from "node:assert/strict";
import { IdpDirectoryRequest, IdpUserState, Tenant, TenantKind } from "@pragmatic-tech-ai/todl-identity";
import type { ISecretStore } from "@pragmatic-tech-ai/todl-identity";
import type { IHttpClient } from "../../http/http-client.js";
import { HttpStatusError } from "../../http/http-status-error.js";
import { MicrosoftGraphDirectorySource } from "../microsoft-graph-directory-source.js";
import { OidcSettingKeys } from "../../pack/oidc-setting-keys.js";

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

class GraphHttp implements IHttpClient
{
    public static readonly AppToken = "app-bearer-xyz";
    public static readonly Base = "https://graph.microsoft.com/v1.0/";
    public static readonly GroupUrl = GraphHttp.Base + "groups/hr-staff/transitiveMembers/microsoft.graph.user?$select=id,accountEnabled";
    public static readonly PageTwoUrl = GraphHttp.Base + "groups/hr-staff/transitiveMembers/microsoft.graph.user?$skiptoken=p2";

    public readonly Bearers: Array<string | undefined> = [];
    public FailUsersWith: number | null = null;

    public async GetJson(url: string, bearer?: string): Promise<unknown>
    {
        this.Bearers.push(bearer);
        if (url === GraphHttp.GroupUrl)
        {
            return { value: [{ id: "alice" }, { id: "dana", accountEnabled: false }], "@odata.nextLink": GraphHttp.PageTwoUrl };
        }
        if (url === GraphHttp.PageTwoUrl)
        {
            return { value: [{ id: "bob" }] };
        }
        if (this.FailUsersWith !== null)
        {
            throw new HttpStatusError(this.FailUsersWith, url);
        }
        if (url.startsWith(GraphHttp.Base + "users/alice")) return { id: "alice", accountEnabled: true };
        if (url.startsWith(GraphHttp.Base + "users/dana")) return { id: "dana", accountEnabled: false };
        throw new HttpStatusError(404, url);
    }

    public async PostForm(_url: string, _fields: ReadonlyMap<string, string>): Promise<unknown>
    {
        return { access_token: GraphHttp.AppToken };
    }
}

class Fixture
{
    public static readonly SecretRef = "graph-secret-ref";

    public static async Source(http: IHttpClient): Promise<MicrosoftGraphDirectorySource>
    {
        const secrets = new MapSecretStore();
        await secrets.Put(Fixture.SecretRef, "graph-client-secret");
        const settings = new Map([
            [OidcSettingKeys.AadTenantId, "aad-1"],
            [OidcSettingKeys.ClientId, "client-1"],
            [OidcSettingKeys.SecretRef, Fixture.SecretRef],
        ]);
        return new MicrosoftGraphDirectorySource(http, secrets, settings);
    }

    public static Tenant(): Tenant
    {
        return new Tenant("t1", TenantKind.Saas, "Acme");
    }
}

class Cases
{
    public static Register(): void
    {
        test("graph source maps enabled, disabled, deleted and pages group members", async () =>
        {
            const http = new GraphHttp();
            const source = await Fixture.Source(http);
            const snapshot = await source.Snapshot(Fixture.Tenant(), new IdpDirectoryRequest(["hr-staff"], ["alice", "dana", "ghost"]));
            assert.equal(snapshot.Authoritative, true);
            assert.equal(snapshot.StateOf("alice"), IdpUserState.Enabled);
            assert.equal(snapshot.StateOf("dana"), IdpUserState.Disabled);
            assert.equal(snapshot.StateOf("ghost"), IdpUserState.Deleted);
            assert.deepEqual([...snapshot.MembersOf("hr-staff")], ["alice", "dana", "bob"]);
            assert.ok(http.Bearers.length >= 5);
            assert.ok(http.Bearers.every((b) => b === GraphHttp.AppToken));

            http.FailUsersWith = 500;
            await assert.rejects(
                source.Snapshot(Fixture.Tenant(), new IdpDirectoryRequest([], ["alice-x"])),
                (e: Error) => !e.message.includes(GraphHttp.AppToken));
        });

        test("graph source rejects on a 500 and returns no partial snapshot", async () =>
        {
            const http = new GraphHttp();
            http.FailUsersWith = 500;
            const source = await Fixture.Source(http);
            await assert.rejects(
                source.Snapshot(Fixture.Tenant(), new IdpDirectoryRequest(["hr-staff"], ["alice-x"])),
                (e: unknown) => e instanceof HttpStatusError && e.Status === 500);
        });
    }
}

Cases.Register();
