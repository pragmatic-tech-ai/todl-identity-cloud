import { OidcIdentityProviderPackBase } from "../pack/oidc-identity-provider-pack-base.js";
import type { OidcPackOptions } from "../pack/oidc-identity-provider-pack-base.js";
import { GoogleIdentityProfile } from "./google-identity-profile.js";

export type GoogleIdentityPackOptions = Omit<OidcPackOptions, "Profile">;

/**
 * Google Identity pack.
 *
 * PR7: Google OIDC has no directory API here, so a user disabled or deleted in Google keeps
 * access until the current session expires; nothing can tell the platform sooner.
 * Admins who need immediate revocation remove the user's assignments and manual team rows,
 * or use an IdP with a directory API.
 */
export class GoogleIdentityPack extends OidcIdentityProviderPackBase
{
    public static Create(opts: GoogleIdentityPackOptions): GoogleIdentityPack
    {
        return new GoogleIdentityPack({ Profile: new GoogleIdentityProfile(), ...opts });
    }
}
