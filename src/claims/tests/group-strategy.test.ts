import { test } from "node:test";
import assert from "node:assert/strict";
import { ClaimArrayGroupStrategy, HostedDomainGroupStrategy } from "../group-strategy.js";

test("ClaimArray returns string arrays", () =>
{
    assert.deepEqual(new ClaimArrayGroupStrategy("groups").GroupsFrom({ groups: ["a", "b"] }), ["a", "b"]);
});

test("ClaimArray non-array or absent gives empty", () =>
{
    const s = new ClaimArrayGroupStrategy("groups");
    assert.deepEqual(s.GroupsFrom({ groups: "x" }), []);
    assert.deepEqual(s.GroupsFrom({}), []);
});

test("ClaimArray keeps only strings", () =>
{
    assert.deepEqual(new ClaimArrayGroupStrategy("groups").GroupsFrom({ groups: ["a", 1, null, "b"] }), ["a", "b"]);
});

test("HostedDomain returns the domain", () =>
{
    assert.deepEqual(new HostedDomainGroupStrategy("hd").GroupsFrom({ hd: "acme.com" }), ["acme.com"]);
});

test("HostedDomain absent or empty gives empty", () =>
{
    const s = new HostedDomainGroupStrategy("hd");
    assert.deepEqual(s.GroupsFrom({}), []);
    assert.deepEqual(s.GroupsFrom({ hd: "" }), []);
});
