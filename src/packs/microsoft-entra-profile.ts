import { ClaimArrayGroupStrategy } from "../claims/group-strategy.js";
import { MicrosoftGraphDirectorySource } from "../directory/microsoft-graph-directory-source.js";
import { OidcProviderProfile } from "../pack/oidc-provider-profile.js";
import { OidcSettingKeys } from "../pack/oidc-setting-keys.js";

/**
 * Microsoft Entra ID (v2.0 endpoint) profile.
 *
 * The principal id is the `oid` claim, which equals the Microsoft Graph object id, so directory
 * sync can address users directly.
 *
 * Groups "overage" boundary: when a user belongs to too many groups, Entra omits the
 * `groups` claim and emits a `_claim_names` / `_claim_sources` overage indicator, which
 * requires a Microsoft Graph call to enumerate the groups. Resolving overage via Graph is
 * OUT OF SCOPE for this phase (documented, not implemented): such a token simply yields
 * empty groups here.
 */
export class MicrosoftEntraProfile extends OidcProviderProfile
{
    private static readonly Scopes: readonly string[] = ["openid", "profile", "email"];
    private static readonly EmailClaim = "email";
    private static readonly NameClaim = "name";
    private static readonly GroupsClaim = "groups";
    private static readonly OidClaim = "oid";
    private static readonly SecretParam = "client_secret";
    private static readonly Host = "https://login.microsoftonline.com/";
    private static readonly IssuerSuffix = "/v2.0";
    private static readonly WellKnownSuffix = "/.well-known/openid-configuration";
    private static readonly MissingTenantError = OidcProviderProfile.MissingSettingPrefix + OidcSettingKeys.AadTenantId;

    public constructor()
    {
        super(
            MicrosoftEntraProfile.Scopes,
            new Map([
                [MicrosoftEntraProfile.EmailClaim, MicrosoftEntraProfile.EmailClaim],
                [MicrosoftEntraProfile.NameClaim, MicrosoftEntraProfile.NameClaim],
            ]),
            new ClaimArrayGroupStrategy(MicrosoftEntraProfile.GroupsClaim),
            MicrosoftEntraProfile.SecretParam,
            MicrosoftEntraProfile.OidClaim);
    }

    /** The oid equals the Graph object id, which the directory source keys in lowercase. */
    public override NormalizeSubject(subject: string): string
    {
        return MicrosoftGraphDirectorySource.Normalize(subject);
    }

    public override ResolveIssuer(settings: ReadonlyMap<string, string>): string
    {
        const tenantId = settings.get(OidcSettingKeys.AadTenantId);
        if (tenantId === undefined || tenantId === "")
        {
            throw new Error(MicrosoftEntraProfile.MissingTenantError);
        }
        return `${MicrosoftEntraProfile.Host}${tenantId}${MicrosoftEntraProfile.IssuerSuffix}`;
    }

    public override ResolveDiscoveryUrl(settings: ReadonlyMap<string, string>): string
    {
        return this.ResolveIssuer(settings) + MicrosoftEntraProfile.WellKnownSuffix;
    }
}
