import { OidcIdentityProviderPackBase } from "../pack/oidc-identity-provider-pack-base.js";
import type { OidcPackOptions } from "../pack/oidc-identity-provider-pack-base.js";
import { MicrosoftEntraProfile } from "./microsoft-entra-profile.js";

export type MicrosoftEntraPackOptions = Omit<OidcPackOptions, "Profile">;

export class MicrosoftEntraPack extends OidcIdentityProviderPackBase
{
    public static Create(opts: MicrosoftEntraPackOptions): MicrosoftEntraPack
    {
        return new MicrosoftEntraPack({ Profile: new MicrosoftEntraProfile(), ...opts });
    }
}
