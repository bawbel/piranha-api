// Tests for worker.js. Run: node --test   (Node 18 or later, no dependencies)
//
// They go through the Worker's own fetch handler, the way Cloudflare calls it, and read
// the response. The expected destinations are written out here on purpose, so a change to
// the constants in worker.js has to be a change to this file too.

import assert from "node:assert/strict";
import { test } from "node:test";

import worker from "./worker.js";

const HOST = "https://api.piranha.bawbel.io";
const AVE_API = "https://api.aveproject.org";
const FALLBACK = "https://github.com/bawbel/piranha-api";

async function go(path, init) {
  const response = await worker.fetch(new Request(HOST + path, init));
  return { status: response.status, location: response.headers.get("location") };
}

// The only places a redirect may ever point: the fallback, or a /records path on the AVE API.
function assertAllowed(location) {
  const target = new URL(location);
  if (location === FALLBACK) return;
  assert.equal(target.origin, AVE_API, `unexpected origin: ${location}`);
  assert.ok(target.pathname === "/records" || target.pathname.startsWith("/records/"), `unexpected path: ${location}`);
}

test("a record link goes to the AVE API with a 301", async () => {
  assert.deepEqual(await go("/records/AVE-2026-00002"), {
    status: 301,
    location: `${AVE_API}/records/AVE-2026-00002`,
  });
});

test("the records list keeps its query string", async () => {
  assert.deepEqual(await go("/records?limit=1&schema=1.1"), {
    status: 301,
    location: `${AVE_API}/records?limit=1&schema=1.1`,
  });
});

test("sub-paths of /records follow", async () => {
  assert.equal((await go("/records/AVE-2026-00002/mitigation")).location, `${AVE_API}/records/AVE-2026-00002/mitigation`);
  assert.equal((await go("/records/")).location, `${AVE_API}/records/`);
});

test("every other path goes to the repository with a 302", async () => {
  const paths = ["/", "/health", "/docs", "/stats/ecosystem", "/registry-scan/latest", "/scan", "/recordsX", "/record"];
  for (const path of paths) {
    assert.deepEqual(await go(path), { status: 302, location: FALLBACK }, path);
  }
});

test("open-redirect attempts never leave the two destinations", async () => {
  const attempts = [
    "//evil.example/records",
    "/records/@evil.example",
    "/records/..//evil.example",
    "/records\\evil.example",
    "/records/%2F%2Fevil.example",
    "/records%2F..%2F..%2Fevil.example",
    "/records?next=https://evil.example",
    "/records?url=//evil.example",
    "/%2e%2e/records",
    "/\\evil.example",
    "//evil.example",
    "/records#https://evil.example",
  ];
  for (const path of attempts) {
    assertAllowed((await go(path)).location);
  }
});

test("the request host and headers never choose the destination", async () => {
  const request = new Request("https://evil.example/records/AVE-2026-00002", {
    headers: { Host: "evil.example", "X-Forwarded-Host": "evil.example", Referer: "https://evil.example/" },
  });
  const response = await worker.fetch(request);
  assert.equal(response.status, 301);
  assert.equal(response.headers.get("location"), `${AVE_API}/records/AVE-2026-00002`);
});

test("any method gets a redirect", async () => {
  for (const method of ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"]) {
    assert.deepEqual(await go("/records/AVE-2026-00002", { method }), {
      status: 301,
      location: `${AVE_API}/records/AVE-2026-00002`,
    });
    assert.deepEqual(await go("/scan", { method }), { status: 302, location: FALLBACK });
  }
});

test("an unparseable URL falls back instead of throwing", async () => {
  for (const bad of ["", "not a url", "http://", "://x"]) {
    const response = await worker.fetch({ url: bad });
    assert.equal(response.status, 302, JSON.stringify(bad));
    assert.equal(response.headers.get("location"), FALLBACK, JSON.stringify(bad));
  }
});
