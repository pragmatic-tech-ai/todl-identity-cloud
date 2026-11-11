import { AuditEvent, AuditEventKind, AuthMethod, AuthenticatedResult, DelegationDepth, Principal } from "@pragmatic-tech-ai/todl-identity";
import type {
    AuthenticationResult,
    Credential,
    IAuditSink,
    IAuthenticator,
    IdentityConfig,
    PresentedSecret,
    Tenant,
} from "@pragmatic-tech-ai/todl-identity";
import type { UpstreamTokenVault } from "../obo/upstream-token-vault.js";
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
        private readonly now: () => Date = () => new Date(),
        private readonly vault?: UpstreamTokenVault)
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
            const principal = this.AdjustForDepth(result.Principal);
            try
            {
                this.directory.Remember(principal);
                if (this.config.DelegationDepth === DelegationDepth.ExternalGrants)
                {
                    await this.groupRoleMapper.ApplyGroups(principal, tenant, this.config.GroupRoleMap);
                }
                await this.RecordAuth(tenant, principal.Id);
            }
            catch (e)
            {
                // The inner authenticator already stored the upstream tokens; a sign-in that does not complete must not keep them.
                await this.TryForget(tenant, principal.Id);
                throw e;
            }
            return new AuthenticatedResult(principal);
        }
        return result;
    }

    private async TryForget(tenant: Tenant, principalId: string): Promise<void>
    {
        try
        {
            await this.vault?.Delete(tenant.Id, principalId);
        }
        catch
        {
            // The original failure is what the caller must see; the delete error is intentionally dropped (it is never logged).
        }
    }

    private AdjustForDepth(principal: Principal): Principal
    {
        if (this.config.DelegationDepth === DelegationDepth.AuthnDirectory)
        {
            return new Principal(principal.Id, principal.TenantId, principal.Kind, principal.Claims, []);
        }
        return principal;
    }

    private async RecordAuth(tenant: Tenant, principalId: string): Promise<void>
    {
        const detail = new Map([[DepthAwareOidcAuthenticator.MethodDetailKey, DepthAwareOidcAuthenticator.OidcMethodValue]]);
        await this.audit.Record(new AuditEvent(AuditEventKind.Authentication, tenant.Id, principalId, this.now(), detail));
    }
}
