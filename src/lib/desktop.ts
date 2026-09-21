import { invoke } from "@tauri-apps/api/core";
import type { AppSnapshot, CoreStatus, ImportResult } from "./types";
export const desktop = {
  snapshot: () => invoke<AppSnapshot>("get_snapshot"),
  addSubscription: (url: string) =>
    invoke<ImportResult>("add_subscription", { url }),
  importUri: (uri: string) => invoke<ImportResult>("import_uri", { uri }),
  selectServer: (serverId: string | null) =>
    invoke<void>("select_server", { serverId }),
  coreStatus: () => invoke<CoreStatus>("get_core_status"),
  installCore: () => invoke<CoreStatus>("install_core"),
  connect: () => invoke<void>("connect"),
  disconnect: () => invoke<void>("disconnect"),
  connectSystemVpn: () => invoke<void>("connect_system_vpn"),
  disconnectSystemVpn: () => invoke<void>("disconnect_system_vpn"),
};
