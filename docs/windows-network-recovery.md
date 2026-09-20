# Windows TUN recovery ownership

Before a privileged TUN smoke session, VOID writes an atomic journal for a generated session ID. It records only the VOID adapter alias, the Xray PID if one is owned, exact scoped routes created for that session, and lifecycle phase.

Recovery must use this journal to remove only matching owned routes and the matching VOID adapter session. It must never restore a whole route/DNS snapshot, remove similarly named third-party VPN routes, or kill an Xray process by executable name.

The first smoke route is a single controlled IPv4 destination. No default route, physical-adapter DNS, permanent route, firewall rule, or IPv6 routing is part of this milestone.
