import { test } from "node:test";
import assert from "node:assert/strict";
import { AuthMethod, AuthenticatedResult, AuditEventKind, Credential, DelegationDepth, PresentedSecret } from "@pragmatic-tech-ai/todl-identity";
import { UpstreamTokenVault } from "../../obo/upstream-token-vault.js";
import { EntraFixture } from "./entra-fixture.js";

class Golden
{
    private static readonly TestName = "Entra golden flow validates end to end";
    private static readonly OidTestName = "entra principal id is the oid claim";
    private static readonly VaultTestName = "authenticator stores upstream tokens when a vault is configured";
    private static readonly EmailClaim = "email";

    public static Register(): void
    {
        test(Golden.OidTestName, async () =>
        {
            const { pack, tenant, State } = await EntraFixture.EntraFlow(DelegationDepth.ExternalGrants);
            const result = await pack.AuthenticatorFor(AuthMethod.Oidc)!.Authenticate(
                new Credential(AuthMethod.Oidc, State),
                new PresentedSecret(EntraFixture.AuthCode),
                tenant);
            assert.ok(result instanceof AuthenticatedResult);
            const principal = (result as AuthenticatedResult).Principal;
            assert.equal(principal.Id, EntraFixture.Subject);
            assert.notEqual(principal.Id, EntraFixture.SubClaimValue);
        });

        test(Golden.VaultTestName, async () =>
        {
            const { pack, tenant, State, secrets } = await EntraFixture.EntraFlow(DelegationDepth.ExternalGrants, new Map(), EntraFixture.ApiScope);
            const result = await pack.AuthenticatorFor(AuthMethod.Oidc)!.Authenticate(
                new Credential(AuthMethod.Oidc, State),
                new PresentedSecret(EntraFixture.AuthCode),
                tenant);
            assert.ok(result instanceof AuthenticatedResult);
            const stored = await new UpstreamTokenVault(secrets).Get(EntraFixture.TenantId, EntraFixture.Subject);
            assert.equal(stored?.AccessToken, EntraFixture.AccessToken);
            assert.equal(stored?.RefreshToken, EntraFixture.RefreshToken);
        });

        test(Golden.TestName, async () =>
        {
            const { pack, tenant, State, audit, idToken } = await EntraFixture.EntraFlow(DelegationDepth.ExternalGrants);
            const result = await pack.AuthenticatorFor(AuthMethod.Oidc)!.Authenticate(
                new Credential(AuthMethod.Oidc, State),
                new PresentedSecret(EntraFixture.AuthCode),
                tenant);
            assert.ok(result instanceof AuthenticatedResult);
            const principal = (result as AuthenticatedResult).Principal;
            assert.equal(principal.Id, EntraFixture.Subject);
            assert.equal(principal.Claim(Golden.EmailClaim), EntraFixture.Email);
            assert.deepEqual([...principal.Groups], [EntraFixture.Group]);
            const session = await pack.Sessions.Issue(principal);
            assert.ok(await pack.Sessions.Validate(session.Id));
            assert.ok(audit.Events.some((e) => e.Kind === AuditEventKind.Authentication));
            for (const event of audit.Events)
            {
                for (const value of event.Detail.values())
                {
                    assert.ok(!value.includes(EntraFixture.AuthCode));
                    assert.ok(!value.includes(idToken));
                }
            }
        });
    }
}

Golden.Register();
