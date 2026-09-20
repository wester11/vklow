# Windows TUN: first safety milestone

VOID uses native Xray TUN rather than an external tun2socks process. The selected stable Xray `v26.3.27` release includes the required official `wintun.dll`; Xray requires that DLL next to `xray.exe` on Windows.

Before any TUN session, VOID validates a typed minimal TUN configuration through `xray run -test` and checks that exact runtime component. The probe does not create an adapter, add routes, or change DNS.

The current Xray schema uses `autoSystemRoutingTable` as a CIDR list and `autoOutboundsInterface` as an interface selector (`"auto"`), not booleans. A default route is intentionally not used until an ownership journal and verified uplink-loop prevention exist.

The Xray validation probe touches Wintun's device-installation mutex and therefore requires Windows elevation. VOID reports this explicitly as `elevationRequired`; it does not run the GUI as Administrator or silently elevate it. A least-privilege typed helper is required before a real adapter/session smoke test.
