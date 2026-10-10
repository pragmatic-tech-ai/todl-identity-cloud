import { OidcIdentityProviderPackBase } from "../pack/oidc-identity-provider-pack-base.js";
import type { OidcPackOptions } from "../pack/oidc-identity-provider-pack-base.js";

/** Generic OIDC pack: the caller supplies the provider as opts.Profile (a GenericOidcProfile). */
export class GenericOidcPack extends OidcIdentityProviderPackBase
{
    public static Create(opts: OidcPackOptions): GenericOidcPack
    {
        return new GenericOidcPack(opts);
    }
}
