export type Protocol = "vless" | "vmess" | "shadowsocks" | "trojan";
export type ServerHealth = "UNKNOWN" | "TESTING" | "AVAILABLE" | "DEGRADED" | "UNAVAILABLE";
export type ConnectionState = { kind: "idle" | "preparing" | "starting_core" | "connected" | "stopping" | "error"; message?: string };
export interface ServerSummary { id: string; name: string; protocol: Protocol; address: string; port: number; transport?: string; country?: string; health: ServerHealth; latencyMs?: number; }
export interface Subscription { id: string; name: string; updatedAt: string; serverCount: number; }
export interface AppSnapshot { connection: ConnectionState; servers: ServerSummary[]; subscriptions: Subscription[]; selectedServerId: string | null; }
export interface ImportResult { serverCount: number; }
