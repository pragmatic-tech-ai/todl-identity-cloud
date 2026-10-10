import { OidcIdentityProviderPackBase } from "../pack/oidc-identity-provider-pack-base.js";
import type { OidcPackOptions } from "../pack/oidc-identity-provider-pack-base.js";
import { GoogleIdentityProfile } from "./google-identity-profile.js";

export type GoogleIdentityPackOptions = Omit<OidcPackOptions, "Profile">;

export class GoogleIdentityPack extends OidcIdentityProviderPackBase
{
    public static Create(opts: GoogleIdentityPackOptions): GoogleIdentityPack
    {
        return new GoogleIdentityPack({ Profile: new GoogleIdentityProfile(), ...opts });
    }
}
