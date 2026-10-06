import type { Machine } from "~/types";
import { hasPortSpec, parsePolicy } from "~/utils/acl-policy";

export interface NetworkEdge {
  source: string;
  target: string;
  permissions: string[];
}

// Compare addresses as integers so IPv6 compression and CIDR prefixes work.
function address(value: string): { bits: number; value: bigint } | undefined {
  if (!value.includes(":")) {
    const parts = value.split(".");
    if (parts.length !== 4 || parts.some((p) => !/^\d+$/.test(p) || Number(p) > 255)) return;
    return { bits: 32, value: parts.reduce((n, p) => (n << 8n) + BigInt(p), 0n) };
  }
  const halves = value.split("::");
  if (halves.length > 2) return;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const count = left.length + right.length;
  if (count > 8 || (halves.length === 1 && count !== 8) || (halves.length === 2 && count >= 8))
    return;
  const parts = [...left, ...Array<string>(8 - count).fill("0"), ...right];
  if (parts.some((p) => !/^[a-f\d]{1,4}$/i.test(p))) return;
  return { bits: 128, value: parts.reduce((n, p) => (n << 16n) + BigInt(`0x${p}`), 0n) };
}

function contains(prefix: string, ip: string): boolean {
  const [host, width, ...rest] = prefix.split("/");
  const a = address(host);
  const b = address(ip);
  if (!a || !b || a.bits !== b.bits || rest.length) return false;
  const length = width === undefined ? a.bits : Number(width);
  if (width !== undefined && !/^\d+$/.test(width)) return false;
  if (length < 0 || length > a.bits) return false;
  const shift = BigInt(a.bits - length);
  return a.value >> shift === b.value >> shift;
}

export function buildNetworkGraph(nodes: Machine[], raw: string) {
  const parsed = parsePolicy(raw);
  if (!parsed.ok)
    return {
      edges: [] as NetworkEdge[],
      warnings: [`Policy could not be parsed: ${parsed.error}`],
    };
  const policy = parsed.policy;
  const warnings = new Set<string>();
  const unsupported = (selector: string) => {
    warnings.add(`Unresolved selector: ${selector}`);
    return false;
  };
  function matches(
    selector: string,
    node: Machine,
    source: Machine,
    seen = new Set<string>(),
  ): boolean {
    if (selector === "*") return true;
    if (selector === "autogroup:member") return node.tags.length === 0 && !!node.user;
    if (selector === "autogroup:tagged") return node.tags.length > 0;
    if (selector === "autogroup:self")
      return (
        node.tags.length === 0 &&
        source.tags.length === 0 &&
        !!node.user &&
        node.user.id === source.user?.id
      );
    if (selector.startsWith("tag:")) return node.tags.includes(selector);
    if (selector.startsWith("group:")) {
      if (seen.has(selector)) return unsupported(selector);
      const members = policy.groups[selector];
      if (!members) return unsupported(selector);
      return members.some((member) => matches(member, node, source, new Set([...seen, selector])));
    }
    if (selector in policy.hosts)
      return node.ipAddresses.some((ip) => contains(policy.hosts[selector], ip));
    if (address(selector.split("/")[0]))
      return node.ipAddresses.some((ip) => contains(selector, ip));
    if (selector.endsWith("@") || selector.includes("@")) {
      return (
        node.tags.length === 0 &&
        !!node.user &&
        [node.user.name, `${node.user.name}@`, node.user.email].includes(selector)
      );
    }
    return unsupported(selector);
  }
  const defaultAllow = !policy.keyOrder.includes("acls") && !policy.keyOrder.includes("grants");
  if (policy.keyOrder.includes("grants"))
    warnings.add("Grants are not represented; this graph only evaluates ACL rules.");
  const rules = policy.acls.filter((rule) => {
    if (rule.action !== "accept" || Object.keys(rule.extra).length) {
      warnings.add("Rules with unknown actions or conditions are omitted.");
      return false;
    }
    return true;
  });
  const edges: NetworkEdge[] = [];
  for (const source of nodes)
    for (const target of nodes) {
      if (source.id === target.id) continue;
      const permissions = new Set<string>(defaultAllow ? ["Any protocol · all ports"] : []);
      for (const rule of rules) {
        if (!rule.src.some((selector) => matches(selector, source, source))) continue;
        for (const dst of rule.dst) {
          if (!hasPortSpec(dst)) {
            warnings.add(`Destination without ports omitted: ${dst}`);
            continue;
          }
          const split = dst.lastIndexOf(":");
          if (matches(dst.slice(0, split), target, source))
            permissions.add(`${rule.proto || "Any protocol"} · ${dst.slice(split + 1)}`);
        }
      }
      if (permissions.size)
        edges.push({ source: source.id, target: target.id, permissions: [...permissions] });
    }
  return { edges, warnings: [...warnings] };
}
