// Mirrors `AppEvent` and friends in src-tauri/src/node.rs.

export interface Device {
  id: string;
  name: string;
  address: string | null;
  compatible: boolean;
  /** We have this device's key from an earlier pairing. */
  paired: boolean;
}

export interface Me {
  id: string;
  name: string;
  port: number;
  download_dir: string;
  /** A startup problem to show, e.g. a damaged paired-devices file. */
  warning: string | null;
}

/** What a request for one of our shared files adds. */
export interface FetchDetails {
  /** The requester's reason, in its own words (may be empty). */
  reason: string;
  /** The requester says an AI assistant asked for the file. */
  via_assistant: boolean;
  /** The folder the user may let this device fetch from for 10 minutes
   * without asking, along with a yes. */
  grant_folder: string | null;
}

export type PairStatus = "paired" | "declined" | "declined_by_peer" | "timed_out" | "failed";

export type AppEvent =
  | { kind: "devices"; devices: Device[] }
  | {
      kind: "incoming_request";
      transfer_id: string;
      peer_name: string;
      peer_ip: string;
      /** Paired, and proved it holds the paired key. Otherwise anyone could
       * have picked this name. */
      verified: boolean;
      name: string;
      size: number;
      /** Set when the peer asks for one of our shared files instead. */
      fetch: FetchDetails | null;
      /** Set for a folder: how many files it holds (`size` is the total). */
      files?: number | null;
    }
  | { kind: "incoming_expired"; transfer_id: string }
  | { kind: "receive_started"; transfer_id: string; peer_name: string; name: string; size: number }
  | { kind: "receive_progress"; transfer_id: string; bytes: number; size: number; bytes_per_sec: number }
  | { kind: "receive_done"; transfer_id: string; path: string; sha256: string }
  | { kind: "receive_failed"; transfer_id: string; error: string }
  | { kind: "receive_cancelled"; transfer_id: string; by_peer: boolean }
  | { kind: "send_waiting"; transfer_id: string; device_name: string; name: string; size: number; files?: number | null }
  | { kind: "send_progress"; transfer_id: string; bytes: number; size: number; bytes_per_sec: number }
  | { kind: "send_done"; transfer_id: string; sha256: string }
  | { kind: "send_declined"; transfer_id: string }
  | { kind: "send_failed"; transfer_id: string; error: string }
  | { kind: "send_cancelled"; transfer_id: string; by_peer: boolean }
  | { kind: "pair_code"; pair_id: string; device_id: string; device_name: string; code: string; incoming: boolean }
  | { kind: "pair_expired"; pair_id: string }
  | { kind: "pair_done"; device_id: string; device_name: string; status: PairStatus; error: string | null };

export type IncomingRequest = Extract<AppEvent, { kind: "incoming_request" }>;
export type PairCode = Extract<AppEvent, { kind: "pair_code" }>;

/** One line of the audit log (see `opendrop::audit`). */
export interface AuditEntry {
  at_ms: number;
  event: "list" | "request" | "approve" | "decline" | "grant" | "send";
  peer_id?: string;
  peer_name: string;
  file?: string;
  detail?: string;
  via_assistant?: boolean;
}
