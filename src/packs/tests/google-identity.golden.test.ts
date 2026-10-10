import { test } from "node:test";
import assert from "node:assert/strict";
import { AuthMethod, AuthenticatedResult, AuditEventKind, Credential, PresentedSecret, RejectedResult } from "@pragmatic-tech-ai/todl-identity";
import { GoogleFixture } from "./google-fixture.js";

class Golden
{
    private static readonly EmailClaim = "email";
    private static readonly HostedDomainClaim = "hd";
    private static readonly HdPresentName = "Google golden: hd present yields single domain group";
    private static readonly HdAbsentName = "Google golden: hd absent yields empty groups";
    private static readonly WrongIssuerName = "Google golden: token under another issuer is rejected";
    private static readonly NoSecretName = "Google golden: no code or token in audit";
    private static readonly Domain = "acme.com";
    private static readonly EvilIssuer = "https://evil.example";

    public static Register(): void
    {
        test(Golden.HdPresentName, async () =>
        {
            const flow = await GoogleFixture.GoogleFlow({ sub: "u1", email: "a@x.io", [Golden.HostedDomainClaim]: Golden.Domain });
            const result = await Golden.Authenticate(flow);
            assert.ok(result instanceof AuthenticatedResult);
            const principal = (result as AuthenticatedResult).Principal;
            assert.equal(principal.Id, "u1");
            assert.equal(principal.Claim(Golden.EmailClaim), "a@x.io");
            assert.deepEqual([...principal.Groups], [Golden.Domain]);
        });

        test(Golden.HdAbsentName, async () =>
        {
            const flow = await GoogleFixture.GoogleFlow({ sub: "u2", email: "b@x.io" });
            const result = await Golden.Authenticate(flow);
            assert.ok(result instanceof AuthenticatedResult);
            assert.deepEqual([...(result as AuthenticatedResult).Principal.Groups], []);
        });

        test(Golden.WrongIssuerName, async () =>
        {
            const flow = await GoogleFixture.GoogleFlow({ sub: "u3", email: "c@x.io" }, { issuer: Golden.EvilIssuer });
            const result = await Golden.Authenticate(flow);
            assert.ok(result instanceof RejectedResult);
        });

        test(Golden.NoSecretName, async () =>
        {
            const flow = await GoogleFixture.GoogleFlow({ sub: "u1", email: "a@x.io", [Golden.HostedDomainClaim]: Golden.Domain });
            await Golden.Authenticate(flow);
            assert.ok(flow.audit.Events.some((e) => e.Kind === AuditEventKind.Authentication));
            for (const event of flow.audit.Events)
            {
                for (const value of event.Detail.values())
                {
                    assert.ok(!value.includes(GoogleFixture.AuthCode));
                    assert.ok(!value.includes(flow.idToken));
                }
            }
        });
    }

    private static async Authenticate(flow: Awaited<ReturnType<typeof GoogleFixture.GoogleFlow>>)
    {
        return await flow.pack.AuthenticatorFor(AuthMethod.Oidc)!.Authenticate(
            new Credential(AuthMethod.Oidc, flow.State),
            new PresentedSecret(GoogleFixture.AuthCode),
            flow.tenant);
    }
}

Golden.Register();
