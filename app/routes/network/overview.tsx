import { useId, useMemo, useState } from "react";
import { data, useRevalidator } from "react-router";

import Button from "~/components/button";
import Input from "~/components/input";
import Link from "~/components/link";
import PageError from "~/components/page-error";
import { authContext, headscaleLiveStoreContext, requestApiContext } from "~/server/context";
import { nodesResource, usersResource } from "~/server/headscale/live-store";
import { Capabilities } from "~/server/web/roles";
import { buildNetworkGraph } from "~/utils/network-graph";

import type { Route } from "./+types/overview";

export async function loader({ request, context }: Route.LoaderArgs) {
  const auth = context.get(authContext);
  const principal = await auth.require(request);
  if (
    !auth.can(principal, Capabilities.read_machines) ||
    !auth.can(principal, Capabilities.read_policy)
  ) {
    throw data("You need permission to read machines and policy.", { status: 403 });
  }
  const { api } = await context.get(requestApiContext)(request);
  const [snapshot, policy, users] = await Promise.all([
    context.get(headscaleLiveStoreContext).get(nodesResource, api),
    api.policy.get(),
    context.get(headscaleLiveStoreContext).get(usersResource, api),
  ]);
  // A failed policy request must never be interpreted as an allow-all policy.
  const nodes = snapshot.data.map(({ id, givenName, name, ipAddresses, tags, user, online }) => ({
    id,
    name: givenName || name,
    ipAddresses,
    tags,
    owner: user?.name,
    online,
  }));
  return { nodes, ...buildNetworkGraph(snapshot.data, policy.policy, users.data) };
}

export default function Network({ loaderData: { nodes, edges, warnings } }: Route.ComponentProps) {
  const [selected, setSelected] = useState<string>();
  const [search, setSearch] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [zoom, setZoom] = useState(1);
  const revalidator = useRevalidator();
  const marker = useId().replaceAll(":", "");
  const visible = useMemo(
    () =>
      nodes.filter((node) =>
        [node.name, node.owner, ...node.ipAddresses, ...node.tags].some((value) =>
          value?.toLowerCase().includes(search.toLowerCase()),
        ),
      ),
    [nodes, search],
  );
  const focus = visible.find((node) => node.id === selected);
  // Grow the canvas with the fleet so short labels retain breathing room.
  const canvasWidth = Math.max(1000, visible.length * 65);
  const canvasHeight = canvasWidth * 0.72;
  const positions = new Map(
    visible.map((node, index) => {
      const angle = (index * 2 * Math.PI) / Math.max(visible.length, 1) - Math.PI / 2;
      return [
        node.id,
        {
          x: canvasWidth / 2 + (canvasWidth / 2 - 140) * Math.cos(angle),
          y: canvasHeight / 2 + (canvasHeight / 2 - 90) * Math.sin(angle),
        },
      ];
    }),
  );
  const visibleEdges = edges.filter(
    (edge) =>
      positions.has(edge.source) &&
      positions.has(edge.target) &&
      (showAll ||
        (focus && (edge.source === focus.id || edge.target === focus.id)) ||
        (!focus && visible.length <= 12)),
  );
  const colors = { outgoing: "#2563eb", incoming: "#ea580c", overview: "#8b5cf6" };
  const connected = new Set(visibleEdges.flatMap((edge) => [edge.source, edge.target]));
  const details = focus
    ? edges.filter((edge) => edge.source === focus.id || edge.target === focus.id)
    : [];
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-medium">Network graph</h1>
      <p className="text-sm opacity-70">
        Allowed connection initiation from ACLs. Replies can flow back; arrows do not restrict
        response traffic.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <div className="w-64">
          <Input label="Find a machine" value={search} onChange={setSearch} />
        </div>
        <Button onClick={() => revalidator.revalidate()} disabled={revalidator.state !== "idle"}>
          Refresh
        </Button>
        <Button
          onClick={() => {
            setSelected(undefined);
            setZoom(1);
            setSearch("");
            setShowAll(false);
          }}
        >
          Reset
        </Button>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={showAll}
            onChange={(event) => setShowAll(event.target.checked)}
          />
          All connections
        </label>
        <label className="flex items-center gap-2 text-sm">
          Zoom
          <input
            aria-label="Graph zoom"
            type="range"
            min="1"
            max="3"
            step="0.25"
            value={zoom}
            onChange={(event) => setZoom(Number(event.target.value))}
          />
        </label>
      </div>
      {warnings.length > 0 && (
        <details className="rounded border border-amber-500 p-3 text-sm">
          <summary>Partial graph — {warnings.length} policy limitations</summary>
          <ul className="list-inside list-disc">
            {warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </details>
      )}
      <div className="flex flex-wrap gap-4 text-sm">
        <span className="text-blue-600">→ Outgoing</span>
        <span className="text-orange-600">→ Incoming</span>
        <span className="text-violet-500">→ Overview</span>
        <span>
          {nodes.length} machines · {edges.length} allowed connections
        </span>
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px]">
        <div className="overflow-auto rounded-xl border border-mist-300 bg-mist-50 dark:border-mist-700 dark:bg-mist-950">
          {visible.length === 0 ? (
            <p className="p-8">No matching machines.</p>
          ) : (
            <>
              {visible.length > 12 && !focus && !showAll && (
                <p className="px-4 pt-3 text-sm opacity-70">
                  Select a machine to see its connections.
                </p>
              )}
              <svg
                role="group"
                aria-label="Allowed network connections"
                viewBox={`0 0 ${canvasWidth} ${canvasHeight}`}
                style={{ width: `${zoom * 100}%`, minWidth: canvasWidth * 0.8 }}
              >
                <defs>
                  {Object.entries(colors).map(([key, color]) => (
                    <marker
                      key={key}
                      id={`${marker}-${key}`}
                      viewBox="0 0 10 10"
                      refX="9"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill={color} />
                    </marker>
                  ))}
                </defs>
                {visibleEdges.map((edge) => {
                  const a = positions.get(edge.source)!;
                  const b = positions.get(edge.target)!;
                  const dx = b.x - a.x,
                    dy = b.y - a.y,
                    distance = Math.hypot(dx, dy);
                  const color = focus
                    ? edge.source === focus.id
                      ? "outgoing"
                      : "incoming"
                    : "overview";
                  const start = { x: a.x + (dx / distance) * 25, y: a.y + (dy / distance) * 25 };
                  const end = { x: b.x - (dx / distance) * 30, y: b.y - (dy / distance) * 30 };
                  return (
                    <path
                      key={`${edge.source}-${edge.target}`}
                      d={`M ${start.x} ${start.y} Q ${(a.x + b.x) / 2 - (dy / distance) * 22} ${(a.y + b.y) / 2 + (dx / distance) * 22} ${end.x} ${end.y}`}
                      fill="none"
                      stroke={colors[color]}
                      strokeWidth="2"
                      opacity={focus ? 0.85 : 0.35}
                      markerEnd={`url(#${marker}-${color})`}
                    >
                      <title>
                        {nodes.find((n) => n.id === edge.source)?.name} →{" "}
                        {nodes.find((n) => n.id === edge.target)?.name}:{" "}
                        {edge.permissions.join(", ")}
                      </title>
                    </path>
                  );
                })}
                {visible.map((node) => {
                  const point = positions.get(node.id)!;
                  return (
                    <g
                      key={node.id}
                      role="button"
                      tabIndex={0}
                      aria-label={`Show connections for ${node.name}`}
                      aria-pressed={node.id === focus?.id}
                      onClick={() => setSelected(node.id === selected ? undefined : node.id)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelected(node.id === selected ? undefined : node.id);
                        }
                      }}
                      className="cursor-pointer outline-none focus:stroke-blue-500"
                      opacity={focus && node.id !== focus.id && !connected.has(node.id) ? 0.35 : 1}
                    >
                      <title>
                        {node.name} · {node.online ? "Online" : "Offline"}
                      </title>
                      <circle
                        cx={point.x}
                        cy={point.y}
                        r={node.id === focus?.id ? 25 : 20}
                        fill={node.id === focus?.id ? "#2563eb" : "#64748b"}
                      />
                      <circle
                        cx={point.x + 15}
                        cy={point.y - 15}
                        r="5"
                        fill={node.online ? "#22c55e" : "#94a3b8"}
                      />
                      <text
                        x={point.x}
                        y={point.y + 42}
                        textAnchor="middle"
                        fill="currentColor"
                        stroke="none"
                        fontSize="12"
                      >
                        {node.name.length > 18 ? `${node.name.slice(0, 16)}…` : node.name}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </>
          )}
        </div>
        <aside className="min-w-0 space-y-3 rounded-xl border border-mist-300 p-4 text-sm dark:border-mist-700">
          {focus ? (
            <>
              <Link styled to={`/machines/${focus.id}`}>
                {focus.name}
              </Link>
              <p>
                {focus.online ? "Online" : "Offline"} · {focus.owner || "Tag-owned"}
              </p>
              <p className="break-all opacity-70">{focus.ipAddresses.join(" · ")}</p>
              <p className="break-all opacity-70">{focus.tags.join(" · ")}</p>
              <p>{details.length} allowed connections</p>
              <div className="max-h-[440px] space-y-3 overflow-auto">
                {details.map((edge) => {
                  const outgoing = edge.source === focus.id;
                  const peer = nodes.find(
                    (node) => node.id === (outgoing ? edge.target : edge.source),
                  )!;
                  return (
                    <div
                      key={`${edge.source}-${edge.target}`}
                      className="border-t border-mist-300 pt-2 dark:border-mist-700"
                    >
                      <button
                        className={`text-left ${outgoing ? "text-blue-600" : "text-orange-600"}`}
                        onClick={() => setSelected(peer.id)}
                      >
                        {outgoing ? "→" : "←"} {peer.name}
                      </button>
                      <p className="opacity-70">{edge.permissions.join("; ")}</p>
                    </div>
                  );
                })}
              </div>
            </>
          ) : (
            <p className="opacity-70">
              Select a machine for addresses, ports and allowed directions. This shows policy
              permissions, not live reachability. Subnet destinations and internet access are
              outside this machine graph.
            </p>
          )}
        </aside>
      </div>
    </div>
  );
}

export function ErrorBoundary({ error }: Route.ErrorBoundaryProps) {
  return <PageError error={error} page="Network graph" />;
}
