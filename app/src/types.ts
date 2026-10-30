// Mirrors `AppEvent` and friends in src-tauri/src/node.rs.

export interface Device {
  id: string;
  name: string;
  address: string | null;
  compatible: boolean;
}

export interface Me {
  id: string;
  name: string;
  port: number;
  download_dir: string;
}

export type AppEvent =
  | { kind: "devices"; devices: Device[] }
  | { kind: "incoming_request"; transfer_id: string; peer_name: string; peer_ip: string; name: string; size: number }
  | { kind: "incoming_expired"; transfer_id: string }
  | { kind: "receive_started"; transfer_id: string; peer_name: string; name: string; size: number }
  | { kind: "receive_progress"; transfer_id: string; bytes: number; size: number; bytes_per_sec: number }
  | { kind: "receive_done"; transfer_id: string; path: string; sha256: string }
  | { kind: "receive_failed"; transfer_id: string; error: string }
  | { kind: "send_waiting"; transfer_id: string; device_name: string; name: string; size: number }
  | { kind: "send_progress"; transfer_id: string; bytes: number; size: number; bytes_per_sec: number }
  | { kind: "send_done"; transfer_id: string; sha256: string }
  | { kind: "send_declined"; transfer_id: string }
  | { kind: "send_failed"; transfer_id: string; error: string };

export type IncomingRequest = Extract<AppEvent, { kind: "incoming_request" }>;
