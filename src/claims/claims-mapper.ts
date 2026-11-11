import { Principal, PrincipalKind } from "@pragmatic-tech-ai/todl-identity";
import type { IdentityConfig, Tenant } from "@pragmatic-tech-ai/todl-identity";
import { OidcProviderProfile } from "../pack/oidc-provider-profile.js";
import type { GroupStrategy } from "./group-strategy.js";

export class ClaimsMapper
{
    private static readonly MissingSubjectError = "Token has no usable subject claim";

    public constructor(
        private readonly profileDefaults: ReadonlyMap<string, string>,
        private readonly groupStrategy: GroupStrategy,
        private readonly subjectClaim: string = OidcProviderProfile.DefaultSubjectClaim,
        private readonly normalizeSubject: (subject: string) => string = s => s)
    {
    }

    public Map(payload: Record<string, unknown>, tenant: Tenant, config: IdentityConfig): Principal
    {
        const mapping = new Map<string, string>(this.profileDefaults);
        for (const [principalClaim, idpClaim] of config.ClaimsMapping)
        {
            mapping.set(principalClaim, idpClaim);
        }

        const sub = payload[this.subjectClaim];
        if (typeof sub !== "string" || sub.length === 0)
        {
            throw new Error(ClaimsMapper.MissingSubjectError);
        }

        const claims = new Map<string, string>();
        for (const [principalClaim, idpClaim] of mapping)
        {
            const value = payload[idpClaim];
            if (typeof value === "string" || typeof value === "number" || typeof value === "boolean")
            {
                claims.set(principalClaim, String(value));
            }
        }

        const groups = this.groupStrategy.GroupsFrom(payload);
        return new Principal(this.normalizeSubject(sub), tenant.Id, PrincipalKind.User, claims, groups);
    }
}
