import type { IPrincipalDirectory, Principal, Tenant } from "@pragmatic-tech-ai/todl-identity";

export class OidcDirectory implements IPrincipalDirectory
{
    private static readonly KeySeparator = "\u0000";

    private readonly principals = new Map<string, Principal>();

    public Remember(principal: Principal): void
    {
        this.principals.set(OidcDirectory.KeyOf(principal.TenantId, principal.Id), principal);
    }

    public async Lookup(principalId: string, tenant: Tenant): Promise<Principal | null>
    {
        return this.principals.get(OidcDirectory.KeyOf(tenant.Id, principalId)) ?? null;
    }

    public async GroupsOf(principal: Principal): Promise<readonly string[]>
    {
        return principal.Groups;
    }

    private static KeyOf(tenantId: string, principalId: string): string
    {
        return tenantId + OidcDirectory.KeySeparator + principalId;
    }
}
