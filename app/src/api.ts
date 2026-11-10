// The only module that talks to Tauri, so components can be tested with a fake.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import type { AppEvent, AuditEntry, Device, HistoryEntry, Me } from "./types";

/** Where a file drag is, in CSS pixels, and which files it carries. */
export type DragEvent =
  | { type: "over"; x: number; y: number }
  | { type: "drop"; x: number; y: number; paths: string[] }
  | { type: "leave" };

export interface Api {
  me(): Promise<Me>;
  devices(): Promise<Device[]>;
  sendFiles(target: { deviceId?: string; address?: string }, paths: string[]): Promise<string[]>;
  /** `allowFolder`: with a yes to a fetch, let that device fetch from the
   * file's folder for 10 minutes without asking. */
  respond(transferId: string, accept: boolean, allowFolder?: boolean): Promise<boolean>;
  /** Call off a transfer that's waiting or midway, in either direction;
   * the other device is told. A `*_cancelled` event follows. */
  cancelTransfer(transferId: string): Promise<void>;
  pairDevice(deviceId: string): Promise<void>;
  respondPair(pairId: string, accept: boolean): Promise<boolean>;
  unpairDevice(deviceId: string): Promise<boolean>;
  pickFiles(): Promise<string[]>;
  /** The audit log, newest first. */
  audit(): Promise<AuditEntry[]>;
  /** Finished transfers, newest first, kept across restarts. */
  history(): Promise<HistoryEntry[]>;
  /** Open the file browser at a received file or folder from the history. */
  showInFolder(path: string): Promise<void>;
  /** Files picked with "Send with OpenDrop" since the last call. */
  takeSendPaths(): Promise<string[]>;
  /** Whether "Send with OpenDrop" is in the right-click menu; null where
   * it isn't available. */
  contextMenuStatus(): Promise<boolean | null>;
  setContextMenu(enabled: boolean): Promise<void>;
  onEvent(handler: (event: AppEvent) => void): Promise<() => void>;
  onDrag(handler: (event: DragEvent) => void): Promise<() => void>;
}

export const tauriApi: Api = {
  me: () => invoke("me"),
  devices: () => invoke("devices"),
  sendFiles: (target, paths) =>
    invoke("send_files", { deviceId: target.deviceId ?? null, address: target.address ?? null, paths }),
  respond: (transferId, accept, allowFolder) =>
    invoke("respond", { transferId, accept, allowFolder: allowFolder ?? false }),
  cancelTransfer: (transferId) => invoke("cancel_transfer", { transferId }),
  pairDevice: (deviceId) => invoke("pair_device", { deviceId }),
  respondPair: (pairId, accept) => invoke("respond_pair", { pairId, accept }),
  unpairDevice: (deviceId) => invoke("unpair_device", { deviceId }),
  audit: () => invoke("audit"),
  history: () => invoke("history"),
  showInFolder: (path) => invoke("show_in_folder", { path }),
  takeSendPaths: () => invoke("take_send_paths"),
  contextMenuStatus: () => invoke("context_menu_status"),
  setContextMenu: (enabled) => invoke("set_context_menu", { enabled }),
  async pickFiles() {
    const picked = await open({ multiple: true, directory: false });
    if (picked === null) return [];
    return Array.isArray(picked) ? picked : [picked];
  },
  onEvent: (handler) => listen<AppEvent>("opendrop://event", (e) => handler(e.payload)),
  onDrag: (handler) =>
    getCurrentWebview().onDragDropEvent((e) => {
      const p = e.payload;
      if (p.type === "enter" || p.type === "over") {
        handler({ type: "over", ...toCssPoint(p.position, window.devicePixelRatio, navigator.userAgent) });
      } else if (p.type === "drop") {
        handler({ type: "drop", ...toCssPoint(p.position, window.devicePixelRatio, navigator.userAgent), paths: p.paths });
      } else {
        handler({ type: "leave" });
      }
    }),
};

/** Turn a drag position from Tauri into CSS pixels for `elementFromPoint`.
 *  Windows and Linux report physical pixels, so we divide by the device
 *  pixel ratio. macOS already reports logical (CSS) pixels: dividing there
 *  halved the point on a Retina screen, so a drop only landed on a card when
 *  the pointer was at twice its position. */
export function toCssPoint(
  position: { x: number; y: number },
  ratio: number | undefined,
  userAgent: string,
): { x: number; y: number } {
  const scale = /Macintosh|Mac OS X/.test(userAgent) ? 1 : ratio || 1;
  return { x: position.x / scale, y: position.y / scale };
}
