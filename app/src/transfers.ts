// What the window shows: devices, incoming requests and transfers, updated
// by one pure reducer so it can be tested without Tauri.

import type { AppEvent, Device, IncomingRequest } from "./types";

export type TransferStatus = "waiting" | "active" | "done" | "declined" | "failed";

export interface Transfer {
  id: string;
  direction: "send" | "receive";
  name: string;
  /** The other device. */
  peer: string;
  size: number;
  bytes: number;
  bytesPerSec: number;
  status: TransferStatus;
  /** Saved path (received), or the error. */
  detail?: string;
  sha256?: string;
}

export interface State {
  devices: Device[];
  /** Oldest first; the dialog shows the first. */
  requests: IncomingRequest[];
  /** Newest first. */
  transfers: Transfer[];
}

export const initialState: State = { devices: [], requests: [], transfers: [] };

export type Action = AppEvent | { kind: "set_devices"; devices: Device[] } | { kind: "answered"; transfer_id: string };

export function reducer(state: State, action: Action): State {
  const update = (id: string, change: Partial<Transfer>): State => ({
    ...state,
    transfers: state.transfers.map((t) => (t.id === id ? { ...t, ...change } : t)),
  });
  const add = (t: Transfer): State => ({
    ...state,
    transfers: [t, ...state.transfers.filter((x) => x.id !== t.id)],
  });
  const dropRequest = (id: string): State => ({
    ...state,
    requests: state.requests.filter((r) => r.transfer_id !== id),
  });

  switch (action.kind) {
    case "devices":
    case "set_devices":
      return { ...state, devices: action.devices };
    case "incoming_request":
      return { ...state, requests: [...state.requests, action] };
    case "incoming_expired":
    case "answered":
      return dropRequest(action.transfer_id);
    case "receive_started":
      return add({
        id: action.transfer_id,
        direction: "receive",
        name: action.name,
        peer: action.peer_name,
        size: action.size,
        bytes: 0,
        bytesPerSec: 0,
        status: "active",
      });
    case "send_waiting":
      return add({
        id: action.transfer_id,
        direction: "send",
        name: action.name,
        peer: action.device_name,
        size: action.size,
        bytes: 0,
        bytesPerSec: 0,
        status: "waiting",
      });
    case "receive_progress":
    case "send_progress":
      return update(action.transfer_id, { bytes: action.bytes, bytesPerSec: action.bytes_per_sec, status: "active" });
    case "receive_done":
      return update(action.transfer_id, { status: "done", detail: action.path, sha256: action.sha256 });
    case "send_done": {
      const t = state.transfers.find((x) => x.id === action.transfer_id);
      return update(action.transfer_id, { status: "done", sha256: action.sha256, bytes: t?.size ?? 0 });
    }
    case "send_declined":
      return update(action.transfer_id, { status: "declined" });
    case "receive_failed":
    case "send_failed":
      return update(action.transfer_id, { status: "failed", detail: action.error });
  }
}

export function formatSize(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  return unit === 0 ? `${bytes} B` : `${value.toFixed(1)} ${units[unit]}`;
}

export function formatSpeed(bytesPerSec: number): string {
  return `${formatSize(Math.round(bytesPerSec))}/s`;
}
