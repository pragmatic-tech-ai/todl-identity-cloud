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

    public async Put(tenantId: string, principalId: string, tokens: UpstreamTokens): Promise<void>
    {
        const body = { [UpstreamTokenVault.AccessField]: tokens.AccessToken, [UpstreamTokenVault.RefreshField]: tokens.RefreshToken };
        await this.secrets.Put(UpstreamTokenVault.Reference(tenantId, principalId), JSON.stringify(body));
    }

    public async Get(tenantId: string, principalId: string): Promise<UpstreamTokens | null>
    {
        const raw = await this.secrets.Get(UpstreamTokenVault.Reference(tenantId, principalId));
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

    public async Delete(tenantId: string, principalId: string): Promise<void>
    {
        await this.secrets.Delete(UpstreamTokenVault.Reference(tenantId, principalId));
    }

    private static Reference(tenantId: string, principalId: string): string
    {
        return UpstreamTokenVault.ReferencePrefix + tenantId + UpstreamTokenVault.ReferenceSeparator + principalId;
    }
}
