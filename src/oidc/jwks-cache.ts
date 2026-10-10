import { createLocalJWKSet } from "jose";
import type { JSONWebKeySet } from "jose";
import type { IHttpClient } from "../http/http-client.js";

export class JwksCache
{
    private readonly cache = new Map<string, ReturnType<typeof createLocalJWKSet>>();

    public constructor(private readonly http: IHttpClient)
    {
    }

    public async KeySet(jwksUri: string): Promise<ReturnType<typeof createLocalJWKSet>>
    {
        const existing = this.cache.get(jwksUri);
        if (existing)
        {
            return existing;
        }
        const jwks = await this.http.GetJson(jwksUri) as JSONWebKeySet;
        const set = createLocalJWKSet(jwks);
        this.cache.set(jwksUri, set);
        return set;
    }

    public async Refresh(jwksUri: string): Promise<ReturnType<typeof createLocalJWKSet>>
    {
        this.cache.delete(jwksUri);
        return this.KeySet(jwksUri);
    }
}
