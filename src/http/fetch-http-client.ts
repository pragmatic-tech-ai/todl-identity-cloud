import type { IHttpClient } from "./http-client.js";
import { HttpStatusError } from "./http-status-error.js";

export class FetchHttpClient implements IHttpClient
{
    private static readonly HttpsProtocol = "https:";
    private static readonly TimeoutMs = 10000;
    private static readonly NonHttpsMessage = "Only https URLs are permitted";
    private static readonly PostMethod = "POST";
    private static readonly RedirectMode = "error";
    private static readonly ContentTypeHeader = "content-type";
    private static readonly AuthorizationHeader = "authorization";
    private static readonly BearerPrefix = "Bearer ";
    private static readonly FormContentType = "application/x-www-form-urlencoded";

    public async GetJson(url: string, bearer?: string): Promise<unknown>
    {
        this.RequireHttps(url);
        const headers: Record<string, string> = bearer === undefined ? {} : { [FetchHttpClient.AuthorizationHeader]: FetchHttpClient.BearerPrefix + bearer };
        const res = await fetch(url, { redirect: FetchHttpClient.RedirectMode, headers, signal: AbortSignal.timeout(FetchHttpClient.TimeoutMs) });
        return this.ReadJson(res);
    }

    public async PostForm(url: string, fields: ReadonlyMap<string, string>): Promise<unknown>
    {
        this.RequireHttps(url);
        const res = await fetch(url, { method: FetchHttpClient.PostMethod, redirect: FetchHttpClient.RedirectMode, headers: { [FetchHttpClient.ContentTypeHeader]: FetchHttpClient.FormContentType }, body: new URLSearchParams([...fields]).toString(), signal: AbortSignal.timeout(FetchHttpClient.TimeoutMs) });
        return this.ReadJson(res);
    }

    private RequireHttps(url: string): void
    {
        const parsed = new URL(url);
        if (parsed.protocol !== FetchHttpClient.HttpsProtocol)
        {
            throw new Error(FetchHttpClient.NonHttpsMessage);
        }
    }

    private async ReadJson(res: Response): Promise<unknown>
    {
        if (!res.ok)
        {
            throw new HttpStatusError(res.status);
        }
        return await res.json();
    }
}
