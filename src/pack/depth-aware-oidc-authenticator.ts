import { AuditEvent, AuditEventKind, AuthMethod, AuthenticatedResult, DelegationDepth, Principal } from "@pragmatic-tech-ai/todl-identity";
import type {
    AuthenticationResult,
    Credential,
    IAuditSink,
    IAuthenticator,
    IdentityConfig,
    PresentedSecret,
    Realm,
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

    public BeginAuthorization(realm: Realm): Promise<{ Url: string; State: string }>
    {
        return this.inner.BeginAuthorization(realm);
    }

    public async Authenticate(credential: Credential, presented: PresentedSecret, realm: Realm): Promise<AuthenticationResult>
    {
        const result = await this.inner.Authenticate(credential, presented, realm);
        if (result instanceof AuthenticatedResult)
        {
            const principal = this.AdjustForDepth(result.Principal);
            try
            {
                this.directory.Remember(principal);
                if (this.config.DelegationDepth === DelegationDepth.ExternalGrants)
                {
                    await this.groupRoleMapper.ApplyGroups(principal, realm, this.config.GroupRoleMap);
                }
                await this.RecordAuth(realm, principal.Id);
            }
            catch (e)
            {
                // The inner authenticator already stored the upstream tokens; a sign-in that does not complete must not keep them.
                await this.TryForget(realm, principal.Id);
                throw e;
            }
            return new AuthenticatedResult(principal);
        }
        return result;
    }

    private async TryForget(realm: Realm, principalId: string): Promise<void>
    {
        try
        {
            await this.vault?.Delete(realm.Id, principalId);
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
            return new Principal(principal.Id, principal.RealmId, principal.Kind, principal.Claims, []);
        }
        return principal;
    }

    private async RecordAuth(realm: Realm, principalId: string): Promise<void>
    {
        const detail = new Map([[DepthAwareOidcAuthenticator.MethodDetailKey, DepthAwareOidcAuthenticator.OidcMethodValue]]);
        await this.audit.Record(new AuditEvent(AuditEventKind.Authentication, realm.Id, principalId, this.now(), detail));
    }
}
