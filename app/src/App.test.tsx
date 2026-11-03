import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { Api, DragEvent } from "./api";
import App from "./App";
import type { AppEvent, Device, Me } from "./types";

const pc: Device = { id: "device-pc", name: "AJ-PC", address: "192.168.1.30:45454", compatible: true, paired: false };

function fakeApi(devices: Device[] = [pc]) {
  let emit: (e: AppEvent) => void = () => {};
  let drag: (e: DragEvent) => void = () => {};
  const api = {
    me: vi.fn(async (): Promise<Me> => ({
      id: "device-me",
      name: "AJ's MacBook",
      port: 45454,
      download_dir: "/Users/aj/Downloads/OpenDrop",
      warning: null,
    })),
    devices: vi.fn(async () => devices),
    sendFiles: vi.fn(async () => ["send-1"]),
    respond: vi.fn(async () => true),
    pairDevice: vi.fn(async () => {}),
    respondPair: vi.fn(async () => true),
    unpairDevice: vi.fn(async () => true),
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
    emit({ kind: "incoming_request", transfer_id: "t1", peer_name: "AJ-PC", peer_ip: "192.168.1.30", name: "report.pdf", size: 2_100_000, fetch: null });
    emit({ kind: "incoming_request", transfer_id: "t2", peer_name: "AJ-PC", peer_ip: "192.168.1.30", name: "virus.exe", size: 10, fetch: null });
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

  const fetchRequest = (transfer_id: string, reason: string, via_assistant: boolean): AppEvent => ({
    kind: "incoming_request",
    transfer_id,
    peer_name: "AJ-PC",
    peer_ip: "192.168.1.30",
    name: "q3-report.pdf",
    size: 2_100_000,
    fetch: { reason, via_assistant },
  });

  it("shows who asks for a shared file, the file, that an assistant asked and why", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    await screen.findByRole("button", { name: /AJ-PC/ });
    emit(fetchRequest("f1", "To summarize the Q3 numbers you asked about", true));
    const dialog = screen.getByRole("dialog", { name: "File request" });
    expect(dialog).toHaveTextContent("AJ-PC (192.168.1.30) asks for your file");
    expect(dialog).toHaveTextContent("q3-report.pdf");
    expect(dialog).toHaveTextContent("2.1 MB");
    expect(within(dialog).getByRole("note")).toHaveTextContent("An AI assistant on AJ-PC asked for this file.");
    expect(dialog).toHaveTextContent("Reason given: “To summarize the Q3 numbers you asked about”");
    expect(dialog).toHaveTextContent("Declines automatically in 60s");
    await userEvent.click(within(dialog).getByRole("button", { name: "Approve" }));
    expect(api.respond).toHaveBeenCalledWith("f1", true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("declines a file request, and says so when no assistant or reason is involved", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    await screen.findByRole("button", { name: /AJ-PC/ });
    emit(fetchRequest("f2", "  ", false));
    const dialog = screen.getByRole("dialog", { name: "File request" });
    expect(within(dialog).queryByRole("note")).not.toBeInTheDocument();
    expect(dialog).toHaveTextContent("No reason given.");
    await userEvent.click(within(dialog).getByRole("button", { name: "Decline" }));
    expect(api.respond).toHaveBeenCalledWith("f2", false);
    expect(api.respond).toHaveBeenCalledTimes(1);
  });

  it("declines a file request nobody answers within 60 seconds", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { api, emit } = fakeApi();
      render(<App api={api} />);
      await screen.findByRole("button", { name: /AJ-PC/ });
      emit(fetchRequest("f3", "why not", true));
      act(() => vi.advanceTimersByTime(59_000));
      expect(screen.getByRole("dialog")).toHaveTextContent("Declines automatically in 1s");
      expect(api.respond).not.toHaveBeenCalled();
      act(() => vi.advanceTimersByTime(1_000));
      expect(api.respond).toHaveBeenCalledWith("f3", false);
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("closes the dialog when the request expires", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    await screen.findByRole("button", { name: /AJ-PC/ });
    emit({ kind: "incoming_request", transfer_id: "t1", peer_name: "AJ-PC", peer_ip: "1.2.3.4", name: "a", size: 1, fetch: null });
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

  const code = (incoming = false): AppEvent => ({
    kind: "pair_code",
    pair_id: "pair-1",
    device_id: "device-pc",
    device_name: "AJ-PC",
    code: "042917",
    incoming,
  });

  it("pairs: shows the code, confirms, then reports success", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    const card = await screen.findByRole("listitem", { name: "AJ-PC" });
    await userEvent.click(within(card).getByRole("button", { name: "Pair" }));
    expect(api.pairDevice).toHaveBeenCalledWith("device-pc");

    emit(code());
    const dialog = screen.getByRole("dialog", { name: "Pair with AJ-PC" });
    expect(within(dialog).getByLabelText("Pairing code")).toHaveTextContent("042 917");
    await userEvent.click(within(dialog).getByRole("button", { name: "Confirm" }));
    expect(api.respondPair).toHaveBeenCalledWith("pair-1", true);
    // Stays up, waiting for the other side.
    expect(screen.getByRole("dialog")).toHaveTextContent("Waiting for AJ-PC to confirm");
    expect(within(screen.getByRole("dialog")).getByRole("button", { name: "Confirm" })).toBeDisabled();

    emit({ kind: "pair_done", device_id: "device-pc", device_name: "AJ-PC", status: "paired", error: null });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Paired with AJ-PC.");
  });

  it("asks about incoming pairing and passes on a cancel", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    await screen.findByRole("listitem", { name: "AJ-PC" });
    emit(code(true));
    const dialog = screen.getByRole("dialog", { name: "AJ-PC wants to pair" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.respondPair).toHaveBeenCalledWith("pair-1", false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    emit({ kind: "pair_done", device_id: "device-pc", device_name: "AJ-PC", status: "declined", error: null });
    expect(screen.getByRole("status")).toHaveTextContent("you cancelled");
  });

  it("gives up after 60 seconds and closes when the other side withdraws", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { api, emit } = fakeApi();
      render(<App api={api} />);
      await screen.findByRole("listitem", { name: "AJ-PC" });
      emit(code());
      expect(screen.getByRole("dialog")).toHaveTextContent("Cancels automatically in 60s");
      act(() => vi.advanceTimersByTime(59_000));
      expect(screen.getByRole("dialog")).toHaveTextContent("in 1s");
      expect(api.respondPair).not.toHaveBeenCalled();
      act(() => vi.advanceTimersByTime(1_000));
      expect(api.respondPair).toHaveBeenCalledWith("pair-1", false);
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      emit({ kind: "pair_done", device_id: "device-pc", device_name: "AJ-PC", status: "timed_out", error: null });
      expect(screen.getByRole("status")).toHaveTextContent("nobody confirmed in time");

      // A code the other side withdraws (it cancelled) just goes away.
      emit({ ...code(), pair_id: "pair-2" } as AppEvent);
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      emit({ kind: "pair_expired", pair_id: "pair-2" });
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows a Paired badge and unpairs from the device menu", async () => {
    const { api, emit } = fakeApi();
    render(<App api={api} />);
    let card = await screen.findByRole("listitem", { name: "AJ-PC" });
    expect(within(card).queryByText("Paired")).not.toBeInTheDocument();
    emit({ kind: "devices", devices: [{ ...pc, paired: true }] });
    card = screen.getByRole("listitem", { name: "AJ-PC" });
    expect(within(card).getByText("Paired")).toBeInTheDocument();
    expect(within(card).queryByRole("button", { name: "Pair" })).not.toBeInTheDocument();
    await userEvent.click(within(card).getByRole("button", { name: "Device menu" }));
    await userEvent.click(within(card).getByRole("menuitem", { name: "Unpair" }));
    expect(api.unpairDevice).toHaveBeenCalledWith("device-pc");
    emit({ kind: "devices", devices: [pc] });
    expect(within(screen.getByRole("listitem", { name: "AJ-PC" })).queryByText("Paired")).not.toBeInTheDocument();
  });

  it("shows startup warnings such as a damaged paired-devices file", async () => {
    const { api } = fakeApi();
    api.me.mockResolvedValueOnce({
      id: "device-me",
      name: "Mac",
      port: 45454,
      download_dir: "/tmp",
      warning: "paired devices file /x/paired-devices.json is unreadable",
    });
    render(<App api={api} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("paired-devices.json is unreadable");
  });
});
