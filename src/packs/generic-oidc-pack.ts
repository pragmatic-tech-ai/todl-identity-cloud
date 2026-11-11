import { OidcIdentityProviderPackBase } from "../pack/oidc-identity-provider-pack-base.js";
import type { OidcPackOptions } from "../pack/oidc-identity-provider-pack-base.js";

/**
 * Generic OIDC pack: the caller supplies the provider as opts.Profile (a GenericOidcProfile).
 *
 * PR7: a generic OIDC provider has no directory API, so a user disabled or deleted in the IdP
 * keeps access until the current session expires; nothing can tell the platform sooner.
 * Admins who need immediate revocation remove the user's assignments and manual team rows,
 * or use an IdP with a directory API.
 */
export class GenericOidcPack extends OidcIdentityProviderPackBase
{
    public static Create(opts: OidcPackOptions): GenericOidcPack
    {
        return new GenericOidcPack(opts);
    }
}
