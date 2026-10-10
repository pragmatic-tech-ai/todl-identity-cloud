export interface GroupStrategy
{
    GroupsFrom(payload: Record<string, unknown>): readonly string[];
}

export class ClaimArrayGroupStrategy implements GroupStrategy
{
    public constructor(private readonly claimName: string)
    {
    }

    public GroupsFrom(payload: Record<string, unknown>): readonly string[]
    {
        const value = payload[this.claimName];
        if (!Array.isArray(value))
        {
            return [];
        }
        return value.filter((v): v is string => typeof v === "string");
    }
}

export class HostedDomainGroupStrategy implements GroupStrategy
{
    public constructor(private readonly claimName: string)
    {
    }

    public GroupsFrom(payload: Record<string, unknown>): readonly string[]
    {
        const value = payload[this.claimName];
        if (typeof value !== "string" || value.length === 0)
        {
            return [];
        }
        return [value];
    }
}
