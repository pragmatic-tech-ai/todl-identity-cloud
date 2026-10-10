import type {
    IAuditSink,
    IdentityConfig,
    IRoleGrantStore,
    ISecretStore,
    ISessionManager,
} from "@pragmatic-tech-ai/todl-identity";
import type { IHttpClient } from "../http/http-client.js";
import type { IOidcFlowStateStore } from "../oidc/flow-state-store.js";
import { OidcIdentityProviderPackBase } from "../pack/oidc-identity-provider-pack-base.js";
import { MicrosoftEntraProfile } from "./microsoft-entra-profile.js";

export interface MicrosoftEntraPackOptions
{
    Config: IdentityConfig;
    Http: IHttpClient;
    FlowStates: IOidcFlowStateStore;
    Secrets: ISecretStore;
    Sessions: ISessionManager;
    Grants: IRoleGrantStore;
    Audit: IAuditSink;
    now?: () => Date;
}

export class MicrosoftEntraPack extends OidcIdentityProviderPackBase
{
    public static Create(opts: MicrosoftEntraPackOptions): MicrosoftEntraPack
    {
        return new MicrosoftEntraPack({ Profile: new MicrosoftEntraProfile(), ...opts });
    }
}
