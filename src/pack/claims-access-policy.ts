import { AccessDecision, Action, Role } from "@pragmatic-tech-ai/todl-identity";
import type { AccessContext, EntityPredicate, IAccessPolicy, ResourceRef } from "@pragmatic-tech-ai/todl-identity";

export class ClaimsAccessPolicy implements IAccessPolicy
{
    private static readonly AllowReason = "granted by identity-provider group role";
    private static readonly DenyReason = "no identity-provider group role permits this action";

    private static readonly FullAccess: readonly Action[] = [Action.Read, Action.Write, Action.Delete, Action.Administer, Action.Connect];

    private static readonly Capabilities: ReadonlyMap<Role, readonly Action[]> = new Map<Role, readonly Action[]>([
        [Role.Viewer, [Action.Read]],
        [Role.Editor, [Action.Read, Action.Write]],
        [Role.Admin, ClaimsAccessPolicy.FullAccess],
        [Role.Owner, ClaimsAccessPolicy.FullAccess],
    ]);

    public constructor(private readonly groupRoleMap: ReadonlyMap<string, Role>)
    {
    }

    public Decide(context: AccessContext, action: Action, _resource: ResourceRef): AccessDecision
    {
        for (const group of context.Principal.Groups)
        {
            const role = this.groupRoleMap.get(group);
            if (role === undefined)
            {
                continue;
            }
            if (ClaimsAccessPolicy.Capabilities.get(role)?.includes(action) === true)
            {
                return AccessDecision.Allow(ClaimsAccessPolicy.AllowReason);
            }
        }
        return AccessDecision.Deny(ClaimsAccessPolicy.DenyReason);
    }

    public EntityFilterFor(_context: AccessContext, _action: Action, _concept: string): EntityPredicate
    {
        return { Matches: () => true };
    }
}
