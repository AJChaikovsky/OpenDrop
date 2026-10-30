import { describe, expect, it } from "vitest";
import { formatSize, formatSpeed, initialState, reducer, type State } from "./transfers";
import type { AppEvent } from "./types";

const run = (events: AppEvent[], start: State = initialState) => events.reduce(reducer, start);

describe("reducer", () => {
  it("follows a send from waiting to done", () => {
    const s = run([
      { kind: "send_waiting", transfer_id: "send-1", device_name: "PC", name: "a.jpg", size: 1000 },
      { kind: "send_progress", transfer_id: "send-1", bytes: 400, size: 1000, bytes_per_sec: 2_000_000 },
    ]);
    expect(s.transfers[0]).toMatchObject({ status: "active", bytes: 400, bytesPerSec: 2_000_000, peer: "PC" });
    const done = run([{ kind: "send_done", transfer_id: "send-1", sha256: "abc" }], s);
    expect(done.transfers[0]).toMatchObject({ status: "done", bytes: 1000, sha256: "abc" });
  });

  it("queues incoming requests and drops them when answered or expired", () => {
    const req = (id: string): AppEvent => ({
      kind: "incoming_request", transfer_id: id, peer_name: "Mac", peer_ip: "10.0.0.2", name: `${id}.txt`, size: 5,
    });
    const s = run([req("t1"), req("t2")]);
    expect(s.requests.map((r) => r.transfer_id)).toEqual(["t1", "t2"]);
    const after = reducer(reducer(s, { kind: "answered", transfer_id: "t1" }), { kind: "incoming_expired", transfer_id: "t2" });
    expect(after.requests).toEqual([]);
  });

  it("records where a received file was saved, and failures", () => {
    const s = run([
      { kind: "receive_started", transfer_id: "r1", peer_name: "Mac", name: "x.bin", size: 10 },
      { kind: "receive_done", transfer_id: "r1", path: "/Downloads/OpenDrop/x.bin", sha256: "ff" },
      { kind: "receive_started", transfer_id: "r2", peer_name: "Mac", name: "y.bin", size: 10 },
      { kind: "receive_failed", transfer_id: "r2", error: "checksum mismatch" },
    ]);
    expect(s.transfers.map((t) => [t.id, t.status, t.detail])).toEqual([
      ["r2", "failed", "checksum mismatch"],
      ["r1", "done", "/Downloads/OpenDrop/x.bin"],
    ]);
  });
});

describe("formatting", () => {
  it("uses decimal units", () => {
    expect(formatSize(999)).toBe("999 B");
    expect(formatSize(2_100_000)).toBe("2.1 MB");
    expect(formatSpeed(45_600_000)).toBe("45.6 MB/s");
  });
});
