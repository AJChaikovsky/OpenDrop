// The only module that talks to Tauri, so components can be tested with a fake.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import type { AppEvent, Device, Me } from "./types";

/** Where a file drag is, in CSS pixels, and which files it carries. */
export type DragEvent =
  | { type: "over"; x: number; y: number }
  | { type: "drop"; x: number; y: number; paths: string[] }
  | { type: "leave" };

export interface Api {
  me(): Promise<Me>;
  devices(): Promise<Device[]>;
  sendFiles(target: { deviceId?: string; address?: string }, paths: string[]): Promise<string[]>;
  respond(transferId: string, accept: boolean): Promise<boolean>;
  pickFiles(): Promise<string[]>;
  onEvent(handler: (event: AppEvent) => void): Promise<() => void>;
  onDrag(handler: (event: DragEvent) => void): Promise<() => void>;
}

export const tauriApi: Api = {
  me: () => invoke("me"),
  devices: () => invoke("devices"),
  sendFiles: (target, paths) =>
    invoke("send_files", { deviceId: target.deviceId ?? null, address: target.address ?? null, paths }),
  respond: (transferId, accept) => invoke("respond", { transferId, accept }),
  async pickFiles() {
    const picked = await open({ multiple: true, directory: false });
    if (picked === null) return [];
    return Array.isArray(picked) ? picked : [picked];
  },
  onEvent: (handler) => listen<AppEvent>("opendrop://event", (e) => handler(e.payload)),
  onDrag: (handler) =>
    getCurrentWebview().onDragDropEvent((e) => {
      const p = e.payload;
      // Positions arrive in physical pixels; the DOM works in CSS pixels.
      const scale = window.devicePixelRatio || 1;
      if (p.type === "enter" || p.type === "over") {
        handler({ type: "over", x: p.position.x / scale, y: p.position.y / scale });
      } else if (p.type === "drop") {
        handler({ type: "drop", x: p.position.x / scale, y: p.position.y / scale, paths: p.paths });
      } else {
        handler({ type: "leave" });
      }
    }),
};
