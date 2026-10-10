import { AuditEvent, AuditEventKind, AuthMethod, AuthenticatedResult, DelegationDepth } from "@pragmatic-tech-ai/todl-identity";
import type {
    AuthenticationResult,
    Credential,
    IAuditSink,
    IAuthenticator,
    IdentityConfig,
    PresentedSecret,
    Tenant,
} from "@pragmatic-tech-ai/todl-identity";
import type { OidcAuthenticator } from "../oidc/oidc-authenticator.js";
import type { GroupRoleMapper } from "../claims/group-role-mapper.js";
import type { OidcDirectory } from "./oidc-directory.js";

export class DepthAwareOidcAuthenticator implements IAuthenticator
{
    private static readonly MethodDetailKey = "method";
    private static readonly OidcMethodValue = "oidc";

    public readonly Method = AuthMethod.Oidc;

    public constructor(
        private readonly inner: OidcAuthenticator,
        private readonly directory: OidcDirectory,
        private readonly groupRoleMapper: GroupRoleMapper,
        private readonly audit: IAuditSink,
        private readonly config: IdentityConfig,
        private readonly now: () => Date = () => new Date())
    {
    }

    public BeginAuthorization(tenant: Tenant): Promise<{ Url: string; State: string }>
    {
        return this.inner.BeginAuthorization(tenant);
    }

    public async Authenticate(credential: Credential, presented: PresentedSecret, tenant: Tenant): Promise<AuthenticationResult>
    {
        const result = await this.inner.Authenticate(credential, presented, tenant);
        if (result instanceof AuthenticatedResult)
        {
            this.directory.Remember(result.Principal);
            if (this.config.DelegationDepth === DelegationDepth.ExternalGrants)
            {
                await this.groupRoleMapper.ApplyGroups(result.Principal, tenant, this.config.GroupRoleMap);
            }
            await this.recordAuth(tenant, result.Principal.Id);
        }
        return result;
    }

    private async recordAuth(tenant: Tenant, principalId: string): Promise<void>
    {
        const detail = new Map([[DepthAwareOidcAuthenticator.MethodDetailKey, DepthAwareOidcAuthenticator.OidcMethodValue]]);
        await this.audit.Record(new AuditEvent(AuditEventKind.Authentication, tenant.Id, principalId, this.now(), detail));
    }
}
