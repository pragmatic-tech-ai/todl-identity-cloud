import type { IPrincipalDirectory, Principal, Realm } from "@pragmatic-tech-ai/todl-identity";

export class OidcDirectory implements IPrincipalDirectory
{
    private static readonly KeySeparator = "\u0000";

    private readonly principals = new Map<string, Principal>();

    public Remember(principal: Principal): void
    {
        this.principals.set(OidcDirectory.KeyOf(principal.RealmId, principal.Id), principal);
    }

    public async Lookup(principalId: string, realm: Realm): Promise<Principal | null>
    {
        return this.principals.get(OidcDirectory.KeyOf(realm.Id, principalId)) ?? null;
    }

    public async GroupsOf(principal: Principal): Promise<readonly string[]>
    {
        return principal.Groups;
    }

    private static KeyOf(realmId: string, principalId: string): string
    {
        return realmId + OidcDirectory.KeySeparator + principalId;
    }
}
