# Network graph

Open **Network** to explore ACL permissions between registered machines. Access
requires permission to read both machines and policy. The view is read-only.

Select a machine to show outgoing connections in blue and incoming connections
in orange. Arrowheads identify the destination; opposite directions use separate
curves. Purple arrows show the overview. The graph only labels machines with
short names; select a machine to see full names, addresses, tags, ports and
protocols in the side panel. Green dots indicate online machines.

Search by name, owner, tag or address. Zoom enlarges the scrollable canvas. For
more than twelve machines, connections stay hidden until a machine is selected;
**All connections** enables the full overview. **Refresh** reloads the data.

Arrows describe allowed connection initiation, not measured connectivity or
one-way response traffic. An offline machine can still have ACL permissions.
A connection means at least one protocol/port is permitted; the panel shows the
actual scope. Missing ACL and grants sections use Headscale's default allow-all;
an explicit empty ACL array allows no connections.

The graph resolves users, groups, tags, host aliases, IPv4/IPv6 addresses and
prefixes, and `autogroup:member`, `autogroup:tagged`, `autogroup:self`.
Tagged machines are identified by their tags rather than their original owner.
Grants, conditional rules and unknown selectors are omitted with a visible
partial-graph notice. Subnet destinations, internet access, SSH authorization and
application capabilities are outside this machine-to-machine ACL view. Policy
fetch errors display an error page instead of assuming unrestricted access.
