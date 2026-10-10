import { test } from "node:test";
import assert from "node:assert/strict";
import { InMemoryOidcFlowStateStore } from "../flow-state-store.js";
import { OidcFlowState } from "../oidc-flow-state.js";

test("Take is single-use", async () =>
{
    const store = new InMemoryOidcFlowStateStore();
    const s = new OidcFlowState("st", "n", "v", "https://app/cb", new Date(Date.now() + 60000));
    await store.Put(s);
    assert.equal(await store.Take("st"), s);
    assert.equal(await store.Take("st"), null);
});

test("expired state is rejected and removed", async () =>
{
    let t = 1000000;
    const store = new InMemoryOidcFlowStateStore(() => new Date(t));
    await store.Put(new OidcFlowState("st", "n", "v", "https://app/cb", new Date(t + 10)));
    t += 50;
    assert.equal(await store.Take("st"), null);
    assert.equal(store.Peek("st"), null);
});

test("Peek is non-consuming", async () =>
{
    const store = new InMemoryOidcFlowStateStore();
    const s = new OidcFlowState("st", "n", "v", "https://app/cb", new Date(Date.now() + 60000));
    await store.Put(s);
    assert.equal(store.Peek("st"), s);
    assert.equal(store.Peek("st"), s);
    assert.equal(await store.Take("st"), s);
    assert.equal(await store.Take("st"), null);
});
