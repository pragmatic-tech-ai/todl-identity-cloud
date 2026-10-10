import type { GroupStrategy } from "../claims/group-strategy.js";
import { OidcProviderProfile } from "../pack/oidc-provider-profile.js";

/**
 * A provider that is nothing but a profile: issuer, discovery URL, scopes, claim mapping and
 * group strategy are all supplied by the caller. No OIDC core changes are needed.
 */
export class GenericOidcProfile extends OidcProviderProfile
{
    private static readonly DefaultSecretParam = "client_secret";

    public constructor(
        private readonly issuer: string,
        private readonly discoveryUrl: string,
        scopes: readonly string[],
        claimsMapping: ReadonlyMap<string, string>,
        groupStrategy: GroupStrategy,
        clientSecretParam?: string)
    {
        super(scopes, claimsMapping, groupStrategy, clientSecretParam ?? GenericOidcProfile.DefaultSecretParam);
    }

    public override ResolveIssuer(_settings: ReadonlyMap<string, string>): string
    {
        return this.issuer;
    }

    public override ResolveDiscoveryUrl(_settings: ReadonlyMap<string, string>): string
    {
        return this.discoveryUrl;
    }
}
