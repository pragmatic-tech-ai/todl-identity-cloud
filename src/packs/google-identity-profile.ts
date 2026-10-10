import { HostedDomainGroupStrategy } from "../claims/group-strategy.js";
import { OidcProviderProfile } from "../pack/oidc-provider-profile.js";

/**
 * Google Identity (OIDC) profile.
 *
 * Google OIDC has NO native group claim. Group membership here derives from the `hd`
 * hosted-domain claim via HostedDomainGroupStrategy: `hd` present yields a single-element
 * group (the domain), absent yields no groups. A deployment wanting finer-grained groups
 * must configure a custom claim through the generic OIDC path (plan 5b Task 2).
 *
 * Google's issuer is FIXED (not tenant-templated), so issuer and discovery URL ignore settings.
 */
export class GoogleIdentityProfile extends OidcProviderProfile
{
    public static readonly GoogleIssuer = "https://accounts.google.com";

    private static readonly Scopes: readonly string[] = ["openid", "profile", "email"];
    private static readonly EmailClaim = "email";
    private static readonly NameClaim = "name";
    private static readonly HostedDomainClaim = "hd";
    private static readonly SecretParam = "client_secret";
    private static readonly WellKnownSuffix = "/.well-known/openid-configuration";

    public constructor()
    {
        super(
            GoogleIdentityProfile.Scopes,
            new Map([
                [GoogleIdentityProfile.EmailClaim, GoogleIdentityProfile.EmailClaim],
                [GoogleIdentityProfile.NameClaim, GoogleIdentityProfile.NameClaim],
            ]),
            new HostedDomainGroupStrategy(GoogleIdentityProfile.HostedDomainClaim),
            GoogleIdentityProfile.SecretParam);
    }

    public override ResolveIssuer(_settings: ReadonlyMap<string, string>): string
    {
        return GoogleIdentityProfile.GoogleIssuer;
    }

    public override ResolveDiscoveryUrl(_settings: ReadonlyMap<string, string>): string
    {
        return GoogleIdentityProfile.GoogleIssuer + GoogleIdentityProfile.WellKnownSuffix;
    }
}
