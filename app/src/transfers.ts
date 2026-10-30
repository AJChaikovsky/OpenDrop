// What the window shows: devices, incoming requests, pairing and transfers,
// updated by one pure reducer so it can be tested without Tauri.

import type { AppEvent, Device, IncomingRequest, PairCode, PairStatus } from "./types";

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
  /** The pairing code on screen; `confirmed` once we said it matches. */
  pairing: (PairCode & { confirmed: boolean }) | null;
  /** How the last pairing ended, until the next one starts. */
  pairNotice: { text: string; ok: boolean } | null;
}

export const initialState: State = { devices: [], requests: [], transfers: [], pairing: null, pairNotice: null };

export type Action =
  | AppEvent
  | { kind: "set_devices"; devices: Device[] }
  | { kind: "answered"; transfer_id: string }
  | { kind: "pair_answered"; pair_id: string; accept: boolean };

const PAIR_TEXT: Record<PairStatus, (name: string) => string> = {
  paired: (name) => `Paired with ${name}.`,
  declined: (name) => `Not paired with ${name}: you cancelled.`,
  declined_by_peer: (name) => `Not paired: ${name} said the codes don't match or cancelled.`,
  timed_out: (name) => `Not paired with ${name}: nobody confirmed in time.`,
  failed: (name) => `Pairing with ${name} failed.`,
};

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
    case "pair_code":
      return { ...state, pairing: { ...action, confirmed: false }, pairNotice: null };
    case "pair_answered":
      if (state.pairing?.pair_id !== action.pair_id) return state;
      // After "matches" keep the code up until the other side answers.
      return { ...state, pairing: action.accept ? { ...state.pairing, confirmed: true } : null };
    case "pair_expired":
      return state.pairing?.pair_id === action.pair_id ? { ...state, pairing: null } : state;
    case "pair_done": {
      const text = PAIR_TEXT[action.status](action.device_name) + (action.error ? ` (${action.error})` : "");
      return {
        ...state,
        pairing: state.pairing?.device_id === action.device_id ? null : state.pairing,
        pairNotice: { text, ok: action.status === "paired" },
      };
    }
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
