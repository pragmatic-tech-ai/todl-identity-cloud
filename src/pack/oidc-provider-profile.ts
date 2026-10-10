import type { GroupStrategy } from "../claims/group-strategy.js";
import { OidcSettingKeys } from "./oidc-setting-keys.js";

export class OidcProviderProfile
{
    private static readonly MissingSettingPrefix = "OIDC provider setting is required: ";
    private static readonly MissingIssuerError = OidcProviderProfile.MissingSettingPrefix + OidcSettingKeys.Issuer;
    private static readonly MissingDiscoveryUrlError = OidcProviderProfile.MissingSettingPrefix + OidcSettingKeys.DiscoveryUrl;

    public constructor(
        public readonly DefaultScopes: readonly string[],
        public readonly DefaultClaimsMapping: ReadonlyMap<string, string>,
        public readonly GroupStrategy: GroupStrategy,
        public readonly ClientSecretParam: string)
    {
    }

    public ResolveIssuer(settings: ReadonlyMap<string, string>): string
    {
        const value = settings.get(OidcSettingKeys.Issuer);
        if (value === undefined || value === "")
        {
            throw new Error(OidcProviderProfile.MissingIssuerError);
        }
        return value;
    }

    public ResolveDiscoveryUrl(settings: ReadonlyMap<string, string>): string
    {
        const value = settings.get(OidcSettingKeys.DiscoveryUrl);
        if (value === undefined || value === "")
        {
            throw new Error(OidcProviderProfile.MissingDiscoveryUrlError);
        }
        return value;
    }
}
