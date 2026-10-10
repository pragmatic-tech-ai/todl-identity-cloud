import { createHash, randomBytes } from "node:crypto";

export class PkceChallenge
{
    private static readonly S256 = "S256";
    private static readonly HashAlgorithm = "sha256";
    private static readonly Encoding = "base64url";
    private static readonly VerifierBytes = 32;

    public readonly Method: string = PkceChallenge.S256;

    private constructor(public readonly Verifier: string, public readonly Challenge: string)
    {
    }

    public static Create(): PkceChallenge
    {
        const verifier = randomBytes(PkceChallenge.VerifierBytes).toString(PkceChallenge.Encoding);
        const challenge = createHash(PkceChallenge.HashAlgorithm).update(verifier).digest(PkceChallenge.Encoding);
        return new PkceChallenge(verifier, challenge);
    }
}
