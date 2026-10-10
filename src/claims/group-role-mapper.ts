import { Grant, ResourceKind, ResourceRef } from "@pragmatic-tech-ai/todl-identity";
import type { IRoleGrantStore, Principal, Role, Tenant } from "@pragmatic-tech-ai/todl-identity";

export class GroupRoleMapper
{
    public constructor(private readonly grants: IRoleGrantStore)
    {
    }

    public async ApplyGroups(principal: Principal, tenant: Tenant, groupRoleMap: ReadonlyMap<string, Role>): Promise<void>
    {
        for (const group of principal.Groups)
        {
            const role = groupRoleMap.get(group);
            if (role === undefined)
            {
                continue;
            }
            await this.grants.Save(new Grant(principal.Id, role, new ResourceRef(ResourceKind.Tenant, tenant.Id, [])));
        }
    }
}
