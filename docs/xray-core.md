# Xray Core distribution model

VOID Desktop accepts core releases only from the official `XTLS/Xray-core` GitHub release channel over HTTPS. For Windows x64, the expected artifact is `Xray-windows-64.zip` with its adjacent `.dgst` asset.

The official release workflow creates the ZIP and writes SHA-256 (along with other digests) to that `.dgst` file. The downloader must obtain both release assets, select the expected asset name, extract its SHA-256 from `.dgst`, verify the downloaded archive and only then stage it. A future downloader will reject redirects outside the explicit GitHub allowlist, archives over its configured limit and any archive path outside its staging root.

Reality TCP configuration is generated through typed serde data, never string interpolation. Its client fields follow upstream naming: `serverName`, `fingerprint`, `password` for the public key and `shortId`. The first inbound remains `127.0.0.1` SOCKS only.

No Xray release is downloaded or executed by the current baseline. That will be enabled only with archive staging, Zip Slip protection, version check and process readiness checks in the Core Manager.
