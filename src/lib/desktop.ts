import { invoke } from "@tauri-apps/api/core";
import type { AppSnapshot, ImportResult } from "./types";
export const desktop = { snapshot: () => invoke<AppSnapshot>("get_snapshot"), addSubscription: (url: string) => invoke<ImportResult>("add_subscription", { url }), importUri: (uri: string) => invoke<ImportResult>("import_uri", { uri }), selectServer: (serverId: string | null) => invoke<void>("select_server", { serverId }), connect: () => invoke<void>("connect"), disconnect: () => invoke<void>("disconnect") };
