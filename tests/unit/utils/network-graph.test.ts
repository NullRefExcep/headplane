import { describe, expect, test } from "vitest";

import type { Machine } from "~/types";
import { buildNetworkGraph } from "~/utils/network-graph";

const nodes = [
  {
    id: "1",
    user: { id: "alice", name: "alice" },
    tags: [],
    ipAddresses: ["100.64.0.1", "fd7a::1"],
  },
  { id: "2", user: { id: "alice", name: "alice" }, tags: [], ipAddresses: ["100.64.0.2"] },
  {
    id: "3",
    user: { id: "alice", name: "alice" },
    tags: ["tag:server"],
    ipAddresses: ["100.64.0.3"],
  },
] as Machine[];
const graph = (policy: unknown) => buildNetworkGraph(nodes, JSON.stringify(policy));

describe("network ACL graph", () => {
  test("keeps direction, unions ports, and excludes tagged nodes from users", () => {
    const result = graph({
      groups: { "group:dev": ["alice@"] },
      acls: [
        { action: "accept", src: ["group:dev"], dst: ["tag:server:22"], proto: "tcp" },
        { action: "accept", src: ["alice@"], dst: ["tag:server:443"] },
      ],
    });
    expect(result.warnings).toEqual([]);
    expect(result.edges.map((e) => [e.source, e.target])).toEqual([
      ["1", "3"],
      ["2", "3"],
    ]);
    expect(result.edges[0].permissions).toEqual(["tcp · 22", "Any protocol · 443"]);
  });
  test("self only includes untagged nodes of the same owner", () => {
    expect(
      graph({
        acls: [{ action: "accept", src: ["autogroup:member"], dst: ["autogroup:self:*"] }],
      }).edges.map((e) => [e.source, e.target]),
    ).toEqual([
      ["1", "2"],
      ["2", "1"],
    ]);
  });
  test("matches IPv4 prefixes, aliases and compressed IPv6 destinations", () => {
    const result = graph({
      hosts: { service: "100.64.0.3/32" },
      acls: [
        { action: "accept", src: ["100.64.0.0/24"], dst: ["service:80", "fd7a:0:0:0:0:0:0:1:22"] },
      ],
    });
    expect(result.edges.map((e) => [e.source, e.target])).toEqual([
      ["1", "3"],
      ["2", "1"],
      ["2", "3"],
      ["3", "1"],
    ]);
  });
  test("distinguishes absent ACLs from explicit deny-all and grants", () => {
    expect(graph({}).edges).toHaveLength(6);
    expect(buildNetworkGraph(nodes, "").edges).toHaveLength(6);
    expect(graph({ acls: [] }).edges).toEqual([]);
    const result = graph({ grants: [{ src: ["*"], dst: ["*"], ip: ["*"] }] });
    expect(result.edges).toEqual([]);
    expect(result.warnings).not.toEqual([]);
  });
  test("does not invent access for malformed policies, conditions or unknown actions", () => {
    expect(buildNetworkGraph(nodes, "broken").edges).toEqual([]);
    const result = graph({
      acls: [
        { action: "deny", src: ["*"], dst: ["*:*"] },
        { action: "accept", src: ["*"], dst: ["*:*"], srcPosture: ["posture:trusted"] },
      ],
    });
    expect(result.edges).toEqual([]);
    expect(result.warnings).not.toEqual([]);
  });
  test("reports unresolved selectors and cyclic groups", () => {
    const result = graph({
      groups: { "group:loop": ["group:loop"] },
      acls: [{ action: "accept", src: ["group:loop", "autogroup:admin"], dst: ["*:*"] }],
    });
    expect(result.edges).toEqual([]);
    expect(result.warnings).toHaveLength(2);
  });
});
