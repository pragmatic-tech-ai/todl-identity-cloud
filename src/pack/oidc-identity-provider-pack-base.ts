import { DelegationDepth } from "@pragmatic-tech-ai/todl-identity";
import type {
    AuthMethod,
    IAccessPolicy,
    IAuditSink,
    IAuthenticator,
    IdentityConfig,
    IIdentityProviderPack,
    IPrincipalDirectory,
    IRoleGrantStore,
    ISecretStore,
    ISessionManager,
    Tenant,
} from "@pragmatic-tech-ai/todl-identity";
import type { IHttpClient } from "../http/http-client.js";
import type { IOidcFlowStateStore } from "../oidc/flow-state-store.js";
import { OidcDiscovery } from "../oidc/oidc-discovery.js";
import { JwksCache } from "../oidc/jwks-cache.js";
import { OidcResolvedConfig } from "../oidc/oidc-resolved-config.js";
import { OidcAuthenticator } from "../oidc/oidc-authenticator.js";
import { ClaimsMapper } from "../claims/claims-mapper.js";
import { GroupRoleMapper } from "../claims/group-role-mapper.js";
import { OidcProviderProfile } from "./oidc-provider-profile.js";
import { OidcSettingKeys } from "./oidc-setting-keys.js";
import { OidcDirectory } from "./oidc-directory.js";
import { ClaimsAccessPolicy } from "./claims-access-policy.js";
import { DepthAwareOidcAuthenticator } from "./depth-aware-oidc-authenticator.js";

export interface OidcPackOptions
{
    Profile: OidcProviderProfile;
    Config: IdentityConfig;
    Http: IHttpClient;
    FlowStates: IOidcFlowStateStore;
    Secrets: ISecretStore;
    Sessions: ISessionManager;
    Grants: IRoleGrantStore;
    Audit: IAuditSink;
    now?: () => Date;
}

export abstract class OidcIdentityProviderPackBase implements IIdentityProviderPack
{
    public readonly DelegationDepth: DelegationDepth;
    public readonly Authenticators: readonly IAuthenticator[];
    public readonly Directory: IPrincipalDirectory;
    public readonly Sessions: ISessionManager;
    public readonly Grants: IRoleGrantStore;
    public readonly Policy?: IAccessPolicy;
    public readonly Audit: IAuditSink;

    private readonly depthAware: DepthAwareOidcAuthenticator;

    public constructor(protected readonly opts: OidcPackOptions)
    {
        const settings = opts.Config.ProviderSettings;
        const discovery = new OidcDiscovery(opts.Http, opts.now);
        const jwks = new JwksCache(opts.Http);
        const claims = new ClaimsMapper(opts.Profile.DefaultClaimsMapping, opts.Profile.GroupStrategy);
        const resolved = new OidcResolvedConfig(
            opts.Profile.ResolveDiscoveryUrl(settings),
            opts.Profile.ResolveIssuer(settings),
            OidcIdentityProviderPackBase.RequireSetting(settings, OidcSettingKeys.ClientId),
            OidcIdentityProviderPackBase.RequireSetting(settings, OidcSettingKeys.RedirectUri),
            opts.Profile.DefaultScopes,
            settings.get(OidcSettingKeys.SecretRef) ?? null,
            opts.Profile.ClientSecretParam);
        const inner = new OidcAuthenticator({
            Http: opts.Http,
            Discovery: discovery,
            Jwks: jwks,
            FlowStates: opts.FlowStates,
            Secrets: opts.Secrets,
            Claims: claims,
            Config: opts.Config,
            Resolved: resolved,
            now: opts.now,
        });
        const directory = new OidcDirectory();
        this.depthAware = new DepthAwareOidcAuthenticator(
            inner,
            directory,
            new GroupRoleMapper(opts.Grants),
            opts.Audit,
            opts.Config,
            opts.now ?? (() => new Date()));
        this.Directory = directory;
        this.Authenticators = [this.depthAware];
        this.DelegationDepth = opts.Config.DelegationDepth;
        this.Sessions = opts.Sessions;
        this.Grants = opts.Grants;
        this.Audit = opts.Audit;
        this.Policy = opts.Config.DelegationDepth === DelegationDepth.FullAuthz
            ? new ClaimsAccessPolicy(opts.Config.GroupRoleMap)
            : undefined;
    }

    public AuthenticatorFor(method: AuthMethod): IAuthenticator | undefined
    {
        return this.Authenticators.find((a) => a.Method === method);
    }

    public BeginAuthorization(tenant: Tenant): Promise<{ Url: string; State: string }>
    {
        return this.depthAware.BeginAuthorization(tenant);
    }

    private static RequireSetting(settings: ReadonlyMap<string, string>, key: string): string
    {
        const value = settings.get(key);
        if (value === undefined || value === "")
        {
            throw new Error(OidcProviderProfile.MissingSettingPrefix + key);
        }
        return value;
    }
}
