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
        for (const groupId of request.GroupIds)
        {
            groups.set(groupId, await this.MembersOf(groupId, bearer));
        }
        const users = new Map<string, IdpUserState>();
        for (const principalId of request.PrincipalIds)
        {
            users.set(principalId, await this.StateOf(principalId, bearer));
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

    private async MembersOf(groupId: string, bearer: string): Promise<string[]>
    {
        const members: string[] = [];
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
                members.push(this.RequireUser(item).id);
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
        if (user.id.toLowerCase() !== principalId.toLowerCase()) throw new Error(MicrosoftGraphDirectorySource.MalformedUserError);
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
