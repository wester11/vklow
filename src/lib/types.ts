export type Protocol = "vless" | "vmess" | "shadowsocks" | "trojan";
export type ServerHealth =
  "UNKNOWN" | "TESTING" | "AVAILABLE" | "DEGRADED" | "UNAVAILABLE";
export type ConnectionState = {
  kind:
    | "idle"
    | "preparing"
    | "validating_config"
    | "starting_core"
    | "waiting_for_proxy"
    | "system_vpn_starting"
    | "system_vpn_connected"
    | "proxy_ready"
    | "connected"
    | "stopping"
    | "crashed"
    | "error";
  message?: string;
  socksPort?: number;
};
export interface ServerSummary {
  id: string;
  name: string;
  protocol: Protocol;
  endpointKind: "domain" | "ipv4" | "ipv6";
  port: number;
  transport?: string;
  country?: string;
  health: ServerHealth;
  latencyMs?: number;
}
export interface Subscription {
  id: string;
  name: string;
  updatedAt: string;
  serverCount: number;
}
export interface AppSnapshot {
  connection: ConnectionState;
  servers: ServerSummary[];
  subscriptions: Subscription[];
  selectedServerId: string | null;
}
export interface ImportResult {
  serverCount: number;
}
export interface CoreStatus {
  installState: "not_installed" | "ready" | "failed";
  activeVersion?: string;
  previousVersion?: string;
  lastError?: string;
}
