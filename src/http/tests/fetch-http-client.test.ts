import { test } from "node:test";
import assert from "node:assert/strict";
import { FetchHttpClient } from "../fetch-http-client.js";

test("FetchHttpClient rejects a non-https URL without calling fetch", async () =>
{
    const client = new FetchHttpClient();
    await assert.rejects(() => client.GetJson("http://insecure.example/x"));
    await assert.rejects(() => client.PostForm("http://insecure.example/x", new Map()));
});
