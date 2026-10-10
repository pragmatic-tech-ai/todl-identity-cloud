import { test } from "node:test";
import assert from "node:assert/strict";
import { FetchHttpClient } from "../fetch-http-client.js";

class FetchStub
{
    public Calls = 0;
    private readonly original = globalThis.fetch;

    public constructor(private readonly response: unknown)
    {
    }

    public Install(): void
    {
        globalThis.fetch = (async () =>
        {
            this.Calls++;
            return this.response;
        }) as unknown as typeof fetch;
    }

    public Restore(): void
    {
        globalThis.fetch = this.original;
    }
}

test("FetchHttpClient rejects a non-https URL without calling fetch", async () =>
{
    const stub = new FetchStub({ ok: true, json: async () => ({}) });
    stub.Install();
    try
    {
        const client = new FetchHttpClient();
        const expected = { message: "Only https URLs are permitted" };
        await assert.rejects(() => client.GetJson("http://insecure.example/x"), expected);
        await assert.rejects(() => client.PostForm("http://insecure.example/x", new Map()), expected);
        assert.equal(stub.Calls, 0);
    }
    finally
    {
        stub.Restore();
    }
});

test("FetchHttpClient throws on a non-2xx response", async () =>
{
    const stub = new FetchStub({ ok: false, status: 500 });
    stub.Install();
    try
    {
        const client = new FetchHttpClient();
        await assert.rejects(() => client.GetJson("https://ok.example/x"));
        await assert.rejects(() => client.PostForm("https://ok.example/x", new Map()));
        assert.equal(stub.Calls, 2);
    }
    finally
    {
        stub.Restore();
    }
});
