import { IdpDirectorySnapshot, IdpUserState } from "@pragmatic-tech-ai/todl-identity";
import type { IdpDirectoryRequest, IIdpDirectorySource, ISecretStore, Tenant } from "@pragmatic-tech-ai/todl-identity";
import type { IHttpClient } from "../http/http-client.js";
import { HttpStatusError } from "../http/http-status-error.js";
import { OidcSettingKeys } from "../pack/oidc-setting-keys.js";

/**
 * Directory source over Microsoft Graph with an app-only (client_credentials) token.
 * Any error other than a 404 rejects the whole snapshot, so a partial snapshot never deprovisions anyone.
 */
export class MicrosoftGraphDirectorySource implements IIdpDirectorySource
{
    public readonly Authoritative = true;

    private static readonly TokenUrlPrefix = "https://login.microsoftonline.com/";
    private static readonly TokenUrlSuffix = "/oauth2/v2.0/token";
    private static readonly GraphBase = "https://graph.microsoft.com/v1.0/";
    private static readonly GraphScope = "https://graph.microsoft.com/.default";
    private static readonly GroupMembersTemplate = "groups/{id}/transitiveMembers/microsoft.graph.user?$select=id,accountEnabled";
    private static readonly UserTemplate = "users/{id}?$select=id,accountEnabled";
    private static readonly IdPlaceholder = "{id}";
    private static readonly GrantTypeParam = "grant_type";
    private static readonly GrantTypeClientCredentials = "client_credentials";
    private static readonly ClientIdParam = "client_id";
    private static readonly ClientSecretParam = "client_secret";
    private static readonly ScopeParam = "scope";
    private static readonly AccessTokenField = "access_token";
    private static readonly ValueField = "value";
    private static readonly NextLinkField = "@odata.nextLink";
    private static readonly IdField = "id";
    private static readonly AccountEnabledField = "accountEnabled";
    private static readonly NotFoundStatus = 404;
    private static readonly MissingSettingPrefix = "Graph directory source setting is required: ";
    private static readonly MissingSecretError = "Graph directory source client secret is not available";
    private static readonly NoTokenError = "Graph token response carried no access token";
    private static readonly ForeignLinkError = "Graph paging link left the Graph endpoint";
    private static readonly MalformedUserError = "Graph response was not a complete user record";
    private static readonly MalformedPageError = "Graph response was not a page of results";
    private static readonly Strictness: Readonly<Record<IdpUserState, number>> =
    {
        [IdpUserState.Unknown]: 0,
        [IdpUserState.Enabled]: 1,
        [IdpUserState.Disabled]: 2,
        [IdpUserState.Deleted]: 3,
    };

    private readonly now: () => Date;

    public constructor(
        private readonly http: IHttpClient,
        private readonly secrets: ISecretStore,
        private readonly settings: ReadonlyMap<string, string>,
        now?: () => Date)
    {
        this.now = now ?? (() => new Date());
    }

    public async Snapshot(_tenant: Tenant, request: IdpDirectoryRequest): Promise<IdpDirectorySnapshot>
    {
        const bearer = await this.AppToken();
        const groups = new Map<string, readonly string[]>();
        const users = new Map<string, IdpUserState>();
        // Every group member gets a state from the accountEnabled already selected, so a member reached only through a
        // linked group is never Unknown (active); a stricter state recorded for the same user always wins.
        for (const groupId of request.GroupIds)
        {
            const members = await this.MembersOf(groupId, bearer);
            groups.set(groupId, members.map(m => MicrosoftGraphDirectorySource.Normalize(m.id)));
            for (const member of members)
            {
                MicrosoftGraphDirectorySource.Record(users, MicrosoftGraphDirectorySource.Normalize(member.id), member.accountEnabled ? IdpUserState.Enabled : IdpUserState.Disabled);
            }
        }
        for (const requestedId of request.PrincipalIds)
        {
            const principalId = MicrosoftGraphDirectorySource.Normalize(requestedId);
            MicrosoftGraphDirectorySource.Record(users, principalId, await this.StateOf(principalId, bearer));
        }
        return new IdpDirectorySnapshot(this.now(), this.Authoritative, users, groups);
    }

    private async AppToken(): Promise<string>
    {
        const aadTenant = this.Require(OidcSettingKeys.AadTenantId);
        const clientId = this.Require(OidcSettingKeys.ClientId);
        const secretRef = this.Require(OidcSettingKeys.SecretRef);
        const secret = await this.secrets.Get(secretRef);
        if (secret === null) throw new Error(MicrosoftGraphDirectorySource.MissingSecretError);
        const fields = new Map<string, string>();
        fields.set(MicrosoftGraphDirectorySource.GrantTypeParam, MicrosoftGraphDirectorySource.GrantTypeClientCredentials);
        fields.set(MicrosoftGraphDirectorySource.ClientIdParam, clientId);
        fields.set(MicrosoftGraphDirectorySource.ClientSecretParam, secret);
        fields.set(MicrosoftGraphDirectorySource.ScopeParam, MicrosoftGraphDirectorySource.GraphScope);
        const url = MicrosoftGraphDirectorySource.TokenUrlPrefix + encodeURIComponent(aadTenant) + MicrosoftGraphDirectorySource.TokenUrlSuffix;
        const response = await this.http.PostForm(url, fields) as Record<string, unknown> | null;
        const token = response?.[MicrosoftGraphDirectorySource.AccessTokenField];
        if (typeof token !== "string" || token === "") throw new Error(MicrosoftGraphDirectorySource.NoTokenError);
        return token;
    }

    /** Graph object ids are GUIDs and case-insensitive; every id is keyed in lowercase so one user is one entry. */
    public static Normalize(id: string): string
    {
        return id.toLowerCase();
    }

    private static Record(users: Map<string, IdpUserState>, principalId: string, state: IdpUserState): void
    {
        const current = users.get(principalId);
        if (current === undefined || MicrosoftGraphDirectorySource.Strictness[state] > MicrosoftGraphDirectorySource.Strictness[current])
        {
            users.set(principalId, state);
        }
    }

    private async MembersOf(groupId: string, bearer: string): Promise<{ id: string; accountEnabled: boolean }[]>
    {
        const members: { id: string; accountEnabled: boolean }[] = [];
        let next: string | null = this.GraphUrl(MicrosoftGraphDirectorySource.GroupMembersTemplate, groupId);
        let first = true;
        while (next !== null)
        {
            let page: Record<string, unknown> | null;
            try
            {
                page = await this.http.GetJson(next, bearer) as Record<string, unknown> | null;
            }
            catch (e)
            {
                // A 404 means the group is gone only on the first request; later it would discard earlier pages.
                if (first && this.IsNotFound(e)) return [];
                throw e;
            }
            first = false;
            const items = page?.[MicrosoftGraphDirectorySource.ValueField];
            if (!Array.isArray(items)) throw new Error(MicrosoftGraphDirectorySource.MalformedPageError);
            for (const item of items)
            {
                members.push(this.RequireUser(item));
            }
            const link = page?.[MicrosoftGraphDirectorySource.NextLinkField];
            next = typeof link === "string" ? this.RequireGraphLink(link) : null;
        }
        return members;
    }

    private async StateOf(principalId: string, bearer: string): Promise<IdpUserState>
    {
        let response: unknown;
        try
        {
            response = await this.http.GetJson(this.GraphUrl(MicrosoftGraphDirectorySource.UserTemplate, principalId), bearer);
        }
        catch (e)
        {
            if (this.IsNotFound(e)) return IdpUserState.Deleted;
            throw e;
        }
        const user = this.RequireUser(response);
        if (MicrosoftGraphDirectorySource.Normalize(user.id) !== principalId) throw new Error(MicrosoftGraphDirectorySource.MalformedUserError);
        return user.accountEnabled ? IdpUserState.Enabled : IdpUserState.Disabled;
    }

    private RequireUser(value: unknown): { id: string; accountEnabled: boolean }
    {
        const record = value as Record<string, unknown> | null;
        const id = record?.[MicrosoftGraphDirectorySource.IdField];
        const enabled = record?.[MicrosoftGraphDirectorySource.AccountEnabledField];
        if (typeof id !== "string" || id === "" || typeof enabled !== "boolean")
        {
            throw new Error(MicrosoftGraphDirectorySource.MalformedUserError);
        }
        return { id, accountEnabled: enabled };
    }

    private GraphUrl(template: string, id: string): string
    {
        return MicrosoftGraphDirectorySource.GraphBase + template.replace(MicrosoftGraphDirectorySource.IdPlaceholder, encodeURIComponent(id));
    }

    private RequireGraphLink(link: string): string
    {
        if (!link.startsWith(MicrosoftGraphDirectorySource.GraphBase)) throw new Error(MicrosoftGraphDirectorySource.ForeignLinkError);
        return link;
    }

    private IsNotFound(e: unknown): boolean
    {
        return e instanceof HttpStatusError && e.Status === MicrosoftGraphDirectorySource.NotFoundStatus;
    }

    private Require(key: string): string
    {
        const value = this.settings.get(key);
        if (value === undefined || value === "") throw new Error(MicrosoftGraphDirectorySource.MissingSettingPrefix + key);
        return value;
    }
}
