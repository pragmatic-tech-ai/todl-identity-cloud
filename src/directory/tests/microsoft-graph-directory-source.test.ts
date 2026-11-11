import { test } from "node:test";
import assert from "node:assert/strict";
import { IdpDirectoryRequest, IdpUserState, Tenant, TenantKind } from "@pragmatic-tech-ai/todl-identity";
import { MapSecretStore } from "../../packs/tests/entra-fixture.js";
import type { IHttpClient } from "../../http/http-client.js";
import { HttpStatusError } from "../../http/http-status-error.js";
import { MicrosoftGraphDirectorySource } from "../microsoft-graph-directory-source.js";
import { OidcSettingKeys } from "../../pack/oidc-setting-keys.js";

class GraphHttp implements IHttpClient
{
    public static readonly AppToken = "app-bearer-xyz";
    public static readonly Base = "https://graph.microsoft.com/v1.0/";
    public static readonly GroupUrl = GraphHttp.Base + "groups/hr-staff/transitiveMembers/microsoft.graph.user?$select=id,accountEnabled";
    public static readonly PageTwoUrl = GraphHttp.Base + "groups/hr-staff/transitiveMembers/microsoft.graph.user?$skiptoken=p2";

    public readonly Bearers: Array<string | undefined> = [];
    public FailUsersWith: number | null = null;
    public PageTwo: unknown[] = [{ id: "bob", accountEnabled: true }];
    public PageTwoStatus: number | null = null;
    public UserBody: unknown = undefined;

    public async GetJson(url: string, bearer?: string): Promise<unknown>
    {
        this.Bearers.push(bearer);
        if (url === GraphHttp.GroupUrl)
        {
            return { value: [{ id: "alice", accountEnabled: true }, { id: "dana", accountEnabled: false }], "@odata.nextLink": GraphHttp.PageTwoUrl };
        }
        if (url === GraphHttp.PageTwoUrl)
        {
            if (this.PageTwoStatus !== null) throw new HttpStatusError(this.PageTwoStatus);
            return { value: this.PageTwo };
        }
        if (this.FailUsersWith !== null)
        {
            throw new HttpStatusError(this.FailUsersWith);
        }
        if (this.UserBody !== undefined) return this.UserBody;
        if (url.startsWith(GraphHttp.Base + "users/alice")) return { id: "alice", accountEnabled: true };
        if (url.startsWith(GraphHttp.Base + "users/dana")) return { id: "dana", accountEnabled: false };
        throw new HttpStatusError(404);
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
            http.PageTwo = [{ id: "bob", accountEnabled: true }, { id: "erin", accountEnabled: false }];
            const source = await Fixture.Source(http);
            const snapshot = await source.Snapshot(Fixture.Tenant(), new IdpDirectoryRequest(["hr-staff"], ["alice", "dana", "ghost"]));
            assert.equal(snapshot.Authoritative, true);
            assert.equal(snapshot.StateOf("erin"), IdpUserState.Disabled);
            assert.equal(snapshot.StateOf("alice"), IdpUserState.Enabled);
            assert.equal(snapshot.StateOf("dana"), IdpUserState.Disabled);
            assert.equal(snapshot.StateOf("ghost"), IdpUserState.Deleted);
            assert.deepEqual([...snapshot.MembersOf("hr-staff")], ["alice", "dana", "bob", "erin"]);
            assert.ok(http.Bearers.length >= 5);
            assert.ok(http.Bearers.every((b) => b === GraphHttp.AppToken));

            const mixed = await source.Snapshot(Fixture.Tenant(), new IdpDirectoryRequest([], ["ALICE"]));
            assert.equal(mixed.StateOf("ALICE"), IdpUserState.Enabled);
            assert.equal(mixed.StateOf("alice"), IdpUserState.Enabled);

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

class StrictCases
{
    public static Register(): void
    {
        test("graph source rejects a 404 on a later page instead of dropping earlier members", async () =>
        {
            const http = new GraphHttp();
            http.PageTwoStatus = 404;
            const source = await Fixture.Source(http);
            await assert.rejects(source.Snapshot(Fixture.Tenant(), new IdpDirectoryRequest(["hr-staff"], [])));
        });

        test("graph source rejects a null user response and an incomplete member entry", async () =>
        {
            const nullUser = new GraphHttp();
            nullUser.UserBody = null;
            await assert.rejects((await Fixture.Source(nullUser)).Snapshot(Fixture.Tenant(), new IdpDirectoryRequest([], ["alice"])));
            const badMember = new GraphHttp();
            badMember.PageTwo = [{ id: "bob" }];
            await assert.rejects((await Fixture.Source(badMember)).Snapshot(Fixture.Tenant(), new IdpDirectoryRequest(["hr-staff"], [])));
        });
    }
}

Cases.Register();
StrictCases.Register();
