import type { ISecretStore } from "@pragmatic-tech-ai/todl-identity";

export class UpstreamTokens
{
    public constructor(
        public readonly AccessToken: string,
        public readonly RefreshToken: string | null)
    {
    }
}

export class UpstreamTokenVault
{
    private static readonly ReferencePrefix = "upstream-token/";
    private static readonly ReferenceSeparator = "/";
    private static readonly AccessField = "accessToken";
    private static readonly RefreshField = "refreshToken";

    public constructor(private readonly secrets: ISecretStore)
    {
    }

    public async Put(realmId: string, principalId: string, tokens: UpstreamTokens): Promise<void>
    {
        const body = { [UpstreamTokenVault.AccessField]: tokens.AccessToken, [UpstreamTokenVault.RefreshField]: tokens.RefreshToken };
        await this.secrets.Put(UpstreamTokenVault.Reference(realmId, principalId), JSON.stringify(body));
    }

    public async Get(realmId: string, principalId: string): Promise<UpstreamTokens | null>
    {
        const raw = await this.secrets.Get(UpstreamTokenVault.Reference(realmId, principalId));
        if (raw === null) return null;
        try
        {
            const body = JSON.parse(raw) as Record<string, unknown>;
            const access = body[UpstreamTokenVault.AccessField];
            const refresh = body[UpstreamTokenVault.RefreshField];
            if (typeof access !== "string") return null;
            return new UpstreamTokens(access, typeof refresh === "string" ? refresh : null);
        }
        catch
        {
            return null;
        }
    }

    public async Delete(realmId: string, principalId: string): Promise<void>
    {
        await this.secrets.Delete(UpstreamTokenVault.Reference(realmId, principalId));
    }

    private static Reference(realmId: string, principalId: string): string
    {
        return UpstreamTokenVault.ReferencePrefix + realmId + UpstreamTokenVault.ReferenceSeparator + principalId;
    }
}
