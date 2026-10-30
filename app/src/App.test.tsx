import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { Api, DragEvent } from "./api";
import App from "./App";
import type { AppEvent, Device } from "./types";

const pc: Device = { id: "device-pc", name: "AJ-PC", address: "192.168.1.30:45454", compatible: true };

function fakeApi(devices: Device[] = [pc]) {
  let emit: (e: AppEvent) => void = () => {};
  let drag: (e: DragEvent) => void = () => {};
  const api = {
    me: vi.fn(async () => ({ id: "device-me", name: "AJ's MacBook", port: 45454, download_dir: "/Users/aj/Downloads/OpenDrop" })),
    devices: vi.fn(async () => devices),
    sendFiles: vi.fn(async () => ["send-1"]),
    respond: vi.fn(async () => true),
    pickFiles: vi.fn(async () => ["/tmp/photo.jpg"]),
    onEvent: vi.fn(async (h: (e: AppEvent) => void) => ((emit = h), () => {})),
    onDrag: vi.fn(async (h: (e: DragEvent) => void) => ((drag = h), () => {})),
  } satisfies Api;
  return { api, emit: (e: AppEvent) => act(() => emit(e)), drag: (e: DragEvent) => act(() => drag(e)) };
}

describe("App", () => {
  it("lists nearby devices and sends picked files to the clicked one", async () => {
    const { api } = fakeApi();
    render(<App api={api} />);
    await userEvent.click(await screen.findByRole("button", { name: /AJ-PC/ }));
    expect(api.sendFiles).toHaveBeenCalledWith({ deviceId: "device-pc" }, ["/tmp/photo.jpg"]);
    expect(screen.getByText(/AJ's MacBook/)).toBeInTheDocument();
  });

  it("updates the list when devices come and go", async () => {
    const { api, emit } = fakeApi([]);
    render(<App api={api} />);
    expect(await screen.findByText(/Looking for devices/)).toBeInTheDocument();
    emit({ kind: "devices", devices: [pc] });
    expect(screen.getByRole("button", { name: /AJ-PC/ })).toBeInTheDocument();
    emit({ kind: "devices", devices: [] });
    expect(screen.queryByRole("button", { name: /AJ-PC/ })).not.toBeInTheDocument();
  });

  it("sends files dropped onto a device card", async () => {
    const { api, drag } = fakeApi();
    render(<App api={api} />);
    const card = (await screen.findByRole("button", { name: /AJ-PC/ })).closest("li")!;
    // jsdom has no layout, so point elementFromPoint at the card.
    document.elementFromPoint = vi.fn(() => card);
    drag({ type: "over", x: 10, y: 10 });
    expect(card).toHaveClass("hovered");
    drag({ type: "drop", x: 10, y: 10, paths: ["/tmp/a.txt", "/tmp/b.txt"] });
    expect(api.sendFiles).toHaveBeenCalledWith({ deviceId: "device-pc" }, ["/tmp/a.txt", "/tmp/b.txt"]);
  });

  it("sends by IP address when a device isn't listed", async () => {
    const { api } = fakeApi([]);
    render(<App api={api} />);
    await userEvent.type(screen.getByLabelText(/Send by IP/), "192.168.1.30");
    await userEvent.click(screen.getByRole("button", { name: "Choose files…" }));
    expect(api.sendFiles).toHaveBeenCalledWith({ address: "192.168.1.30" }, ["/tmp/photo.jpg"]);
  });

  it("asks before receiving and passes on the answer", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    await screen.findByRole("button", { name: /AJ-PC/ });
    emit({ kind: "incoming_request", transfer_id: "t1", peer_name: "AJ-PC", peer_ip: "192.168.1.30", name: "report.pdf", size: 2_100_000 });
    emit({ kind: "incoming_request", transfer_id: "t2", peer_name: "AJ-PC", peer_ip: "192.168.1.30", name: "virus.exe", size: 10 });
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("report.pdf");
    expect(dialog).toHaveTextContent("2.1 MB");
    await userEvent.click(within(dialog).getByRole("button", { name: "Accept" }));
    expect(api.respond).toHaveBeenCalledWith("t1", true);
    // The next request takes its place.
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Decline" }));
    expect(api.respond).toHaveBeenCalledWith("t2", false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("closes the dialog when the request expires", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    await screen.findByRole("button", { name: /AJ-PC/ });
    emit({ kind: "incoming_request", transfer_id: "t1", peer_name: "AJ-PC", peer_ip: "1.2.3.4", name: "a", size: 1 });
    emit({ kind: "incoming_expired", transfer_id: "t1" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows progress and speed, then the result", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    await screen.findByRole("button", { name: /AJ-PC/ });
    emit({ kind: "send_waiting", transfer_id: "send-1", device_name: "AJ-PC", name: "movie.mp4", size: 100_000_000 });
    const row = screen.getByRole("listitem", { name: "movie.mp4" });
    expect(row).toHaveTextContent("Waiting for them to accept");
    emit({ kind: "send_progress", transfer_id: "send-1", bytes: 25_000_000, size: 100_000_000, bytes_per_sec: 50_000_000 });
    expect(row).toHaveTextContent("25%");
    expect(row).toHaveTextContent("50.0 MB/s");
    expect(within(row).getByRole("progressbar")).toHaveAttribute("value", "25");
    emit({ kind: "send_done", transfer_id: "send-1", sha256: "ab" });
    expect(row).toHaveTextContent("Done");
    expect(row).toHaveTextContent("100.0 MB / 100.0 MB");
  });

  it("shows send errors", async () => {
    const { api } = fakeApi();
    api.sendFiles.mockRejectedValueOnce("could not reach the device (no answer)");
    render(<App api={api} />);
    await userEvent.click(await screen.findByRole("button", { name: /AJ-PC/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not reach the device");
  });
});
