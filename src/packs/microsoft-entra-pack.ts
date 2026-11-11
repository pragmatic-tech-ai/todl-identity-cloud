import { OidcIdentityProviderPackBase } from "../pack/oidc-identity-provider-pack-base.js";
import type { OidcPackOptions } from "../pack/oidc-identity-provider-pack-base.js";
import { OidcSettingKeys } from "../pack/oidc-setting-keys.js";
import { MicrosoftGraphDirectorySource } from "../directory/microsoft-graph-directory-source.js";
import { UpstreamTokenVault } from "../obo/upstream-token-vault.js";
import { OnBehalfOfTokenProvider } from "../obo/on-behalf-of-token-provider.js";
import { UnsupportedSourceTokenProvider } from "../obo/unsupported-source-token-provider.js";
import type { IIdpDirectorySource, ISourceTokenProvider } from "@pragmatic-tech-ai/todl-identity";
import { MicrosoftEntraProfile } from "./microsoft-entra-profile.js";

export type MicrosoftEntraPackOptions = Omit<OidcPackOptions, "Profile" | "Vault">;

/**
 * Entra pack. Besides sign-in it exposes a Graph-backed directory source and, when the
 * `apiScope` setting is present, an on-behalf-of source-token provider.
 */
export class MicrosoftEntraPack extends OidcIdentityProviderPackBase
{
    public readonly DirectorySource: IIdpDirectorySource;
    public readonly SourceTokens: ISourceTokenProvider;

    private constructor(opts: OidcPackOptions)
    {
        super(opts);
        const settings = opts.Config.ProviderSettings;
        this.DirectorySource = new MicrosoftGraphDirectorySource(opts.Http, opts.Secrets, settings, opts.now);
        const apiScope = settings.get(OidcSettingKeys.ApiScope);
        this.SourceTokens = apiScope !== undefined && apiScope !== "" && opts.Vault !== undefined
            ? new OnBehalfOfTokenProvider({
                Http: opts.Http,
                Discovery: this.Discovery,
                Resolved: this.Resolved,
                Secrets: opts.Secrets,
                Vault: opts.Vault,
                ApiScope: apiScope,
                now: opts.now,
            })
            : new UnsupportedSourceTokenProvider();
    }

    public static Create(opts: MicrosoftEntraPackOptions): MicrosoftEntraPack
    {
        const apiScope = opts.Config.ProviderSettings.get(OidcSettingKeys.ApiScope);
        const vault = apiScope !== undefined && apiScope !== "" ? new UpstreamTokenVault(opts.Secrets) : undefined;
        return new MicrosoftEntraPack({ Profile: new MicrosoftEntraProfile(), ...opts, Vault: vault });
    }
}
