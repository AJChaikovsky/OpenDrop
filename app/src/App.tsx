import { useCallback, useEffect, useReducer, useState } from "react";
import { tauriApi, type Api } from "./api";
import { formatSize, formatSpeed, initialState, plural, reducer, type Transfer } from "./transfers";
import type { AuditEntry, Device, IncomingRequest, Me, PairCode } from "./types";
import "./App.css";

/** Seconds the receiver has to answer; matches APPROVAL_TIMEOUT in the crate. */
const ANSWER_SECONDS = 60;

/** Seconds both users have to compare pairing codes; matches PAIRING_TIMEOUT. */
export const PAIR_SECONDS = 60;

export default function App({ api = tauriApi }: { api?: Api }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [me, setMe] = useState<Me | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const send = useCallback(
    async (target: { deviceId?: string; address?: string }, paths: string[]) => {
      if (paths.length === 0) return;
      setError(null);
      try {
        await api.sendFiles(target, paths);
      } catch (e) {
        setError(String(e));
      }
    },
    [api],
  );

  useEffect(() => {
    let cleanups: (() => void)[] = [];
    let cancelled = false;
    const keep = (unlisten: () => void) => (cancelled ? unlisten() : cleanups.push(unlisten));
    api.onEvent(dispatch).then(keep);
    api
      .onDrag((drag) => {
        const id = drag.type === "leave" ? null : deviceAt(drag.x, drag.y);
        setHovered(id);
        if (drag.type === "drop" && id) send({ deviceId: id }, drag.paths);
      })
      .then(keep);
    api.me().then(setMe).catch((e) => setError(String(e)));
    api.devices().then((devices) => dispatch({ kind: "set_devices", devices }));
    return () => {
      cancelled = true;
      cleanups.forEach((f) => f());
      cleanups = [];
    };
  }, [api, send]);

  const pickAndSend = async (target: { deviceId?: string; address?: string }) => {
    send(target, await api.pickFiles());
  };

  const answer = (request: IncomingRequest, accept: boolean, allowFolder = false) => {
    dispatch({ kind: "answered", transfer_id: request.transfer_id });
    api.respond(request.transfer_id, accept, accept && allowFolder);
  };

  // The row turns "cancelled" when the matching event arrives; a transfer
  // that ended in the meantime just keeps its final state.
  const cancel = (t: Transfer) => {
    api.cancelTransfer(t.id).catch(() => {});
  };

  const pair = async (device: Device) => {
    setError(null);
    try {
      await api.pairDevice(device.id);
    } catch (e) {
      setError(String(e));
    }
  };

  const unpair = async (device: Device) => {
    setError(null);
    try {
      await api.unpairDevice(device.id);
    } catch (e) {
      setError(String(e));
    }
  };

  const answerPair = (code: PairCode, accept: boolean) => {
    dispatch({ kind: "pair_answered", pair_id: code.pair_id, accept });
    api.respondPair(code.pair_id, accept);
  };

  return (
    <main>
      <header>
        <h1>OpenDrop</h1>
        {me && (
          <p className="me">
            This device: <strong>{me.name}</strong> · files are saved to {me.download_dir}
          </p>
        )}
        {me?.warning && (
          <p className="warning" role="alert">
            {me.warning}
          </p>
        )}
      </header>

      <section>
        <h2>Nearby devices</h2>
        {state.devices.length === 0 ? (
          <p className="empty">Looking for devices on your network… Open OpenDrop on another computer to see it here.</p>
        ) : (
          <ul className="devices">
            {state.devices.map((d) => (
              <DeviceCard
                key={d.id}
                device={d}
                hovered={hovered === d.id}
                onPick={() => pickAndSend({ deviceId: d.id })}
                onPair={() => pair(d)}
                onUnpair={() => unpair(d)}
              />
            ))}
          </ul>
        )}
        <p className="hint">Click a device to choose files, or drag files onto it.</p>
        <AddressForm onSend={(address) => pickAndSend({ address })} />
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {state.pairNotice && (
          <p className={state.pairNotice.ok ? "notice ok" : "notice"} role="status">
            {state.pairNotice.text}
          </p>
        )}
      </section>

      {state.transfers.length > 0 && (
        <section>
          <h2>Transfers</h2>
          <ul className="transfers">
            {state.transfers.map((t) => (
              <TransferRow key={t.id} transfer={t} onCancel={cancel} />
            ))}
          </ul>
        </section>
      )}

      <Activity api={api} />

      {state.pairing ? (
        <PairDialog key={state.pairing.pair_id} pairing={state.pairing} onAnswer={answerPair} />
      ) : (
        state.requests[0] && (
          <RequestDialog key={state.requests[0].transfer_id} request={state.requests[0]} onAnswer={answer} />
        )
      )}
    </main>
  );
}

const EVENT_LABELS: Record<AuditEntry["event"], string> = {
  list: "Listed your shared files",
  request: "Asked for a file",
  approve: "Approved",
  decline: "Declined",
  grant: "Folder access granted",
  send: "Sent",
};

/** The audit log: what other devices listed, asked for and were given or
 * refused, and what this device sent. Loaded when opened. */
function Activity({ api }: { api: Api }) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const load = () =>
    api
      .audit()
      .then((e) => {
        setEntries(e);
        setFailed(null);
      })
      .catch((e) => setFailed(String(e)));
  return (
    <section className="activity">
      <h2>Activity</h2>
      {entries === null ? (
        <button onClick={load}>Show activity</button>
      ) : (
        <>
          <button onClick={load}>Refresh</button>
          {entries.length === 0 ? (
            <p className="empty">Nothing yet. Lists, requests and decisions will show up here.</p>
          ) : (
            <ul className="audit">
              {entries.map((e, i) => (
                <li key={`${e.at_ms}-${i}`} className={`audit-${e.event}`}>
                  <time dateTime={new Date(e.at_ms).toISOString()}>{new Date(e.at_ms).toLocaleString()}</time>{" "}
                  <strong>{EVENT_LABELS[e.event]}</strong> · {e.peer_name}
                  {e.file && <> · {e.file}</>}
                  {e.detail && <span className="detail"> ({e.detail})</span>}
                  {e.via_assistant && <span className="detail"> · AI assistant</span>}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {failed && (
        <p className="error" role="alert">
          {failed}
        </p>
      )}
    </section>
  );
}

/** The device card under a point, by its data attribute. */
function deviceAt(x: number, y: number): string | null {
  const element = document.elementFromPoint(x, y);
  const card = element?.closest<HTMLElement>("[data-device-id]");
  return card?.dataset.deviceId ?? null;
}

function DeviceCard({
  device,
  hovered,
  onPick,
  onPair,
  onUnpair,
}: {
  device: Device;
  hovered: boolean;
  onPick: () => void;
  onPair: () => void;
  onUnpair: () => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <li data-device-id={device.id} className={hovered ? "device hovered" : "device"} aria-label={device.name}>
      <button className="device-main" onClick={onPick} disabled={!device.compatible} title={device.address ?? undefined}>
        <span className="avatar" aria-hidden>
          {device.name.slice(0, 1).toUpperCase()}
        </span>
        <span className="device-name">{device.name}</span>
        <span className="device-address">{device.compatible ? device.address ?? "no address" : "needs an update"}</span>
      </button>
      {device.compatible && (
        <div className="device-pairing">
          {device.paired ? (
            <>
              <span className="badge">Paired</span>
              <button
                className="menu-button"
                aria-label="Device menu"
                aria-haspopup="menu"
                aria-expanded={menuOpen}
                onClick={() => setMenuOpen((open) => !open)}
              >
                ⋯
              </button>
              {menuOpen && (
                <div className="menu" role="menu">
                  <button
                    role="menuitem"
                    onClick={() => {
                      setMenuOpen(false);
                      onUnpair();
                    }}
                  >
                    Unpair
                  </button>
                </div>
              )}
            </>
          ) : (
            <button className="pair-button" onClick={onPair}>
              Pair
            </button>
          )}
        </div>
      )}
    </li>
  );
}

function PairDialog({
  pairing,
  onAnswer,
}: {
  pairing: PairCode & { confirmed: boolean };
  onAnswer: (code: PairCode, accept: boolean) => void;
}) {
  const [left, setLeft] = useState(PAIR_SECONDS);
  useEffect(() => {
    const timer = setInterval(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(timer);
  }, []);
  // Out of time: give up on this side too (the other side does the same).
  useEffect(() => {
    if (left === 0 && !pairing.confirmed) onAnswer(pairing, false);
  }, [left, pairing, onAnswer]);
  const name = pairing.device_name;
  return (
    <div className="backdrop">
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="pair-title">
        <h2 id="pair-title">{pairing.incoming ? `${name} wants to pair` : `Pair with ${name}`}</h2>
        <p>Check that {name} shows the same code:</p>
        <p className="code" aria-label="Pairing code">
          {pairing.code.slice(0, 3)} {pairing.code.slice(3)}
        </p>
        {pairing.confirmed ? (
          <p className="countdown">Waiting for {name} to confirm…</p>
        ) : (
          <p className="countdown">Cancels automatically in {left}s</p>
        )}
        <div className="actions">
          <button onClick={() => onAnswer(pairing, false)}>Cancel</button>
          <button className="primary" onClick={() => onAnswer(pairing, true)} disabled={pairing.confirmed} autoFocus>
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}

function AddressForm({ onSend }: { onSend: (address: string) => void }) {
  const [address, setAddress] = useState("");
  return (
    <form
      className="address"
      onSubmit={(e) => {
        e.preventDefault();
        if (address.trim()) onSend(address.trim());
      }}
    >
      <label htmlFor="address">Not listed? Send by IP address:</label>
      <input id="address" placeholder="192.168.1.20" value={address} onChange={(e) => setAddress(e.target.value)} />
      <button type="submit" disabled={!address.trim()}>
        Choose files…
      </button>
    </form>
  );
}

const STATUS_TEXT: Record<Transfer["status"], string> = {
  waiting: "Waiting for them to accept…",
  active: "",
  done: "Done",
  declined: "Declined",
  failed: "Failed",
  cancelled: "Cancelled",
};

function TransferRow({ transfer: t, onCancel }: { transfer: Transfer; onCancel: (t: Transfer) => void }) {
  const percent = t.size > 0 ? Math.floor((t.bytes / t.size) * 100) : 100;
  const arrow = t.direction === "send" ? `to ${t.peer}` : `from ${t.peer}`;
  return (
    <li className={`transfer ${t.status}`} aria-label={t.name}>
      <div className="transfer-line">
        <span className="transfer-name">
          {t.name}
          {t.files != null && <span className="transfer-files"> · folder, {plural(t.files, "file")}</span>}
        </span>
        <span className="transfer-peer">{arrow}</span>
      </div>
      <progress max={100} value={t.status === "done" ? 100 : percent} />
      <div className="transfer-line small">
        <span>
          {formatSize(t.status === "done" ? t.size : t.bytes)} / {formatSize(t.size)}
        </span>
        <span className="transfer-status">
          {t.status === "active" ? `${percent}% · ${formatSpeed(t.bytesPerSec)}` : STATUS_TEXT[t.status]}
          {t.status === "done" && t.bytesPerSec > 0 && ` · ${formatSpeed(t.bytesPerSec)}`}
        </span>
      </div>
      {t.detail && <div className="transfer-detail">{t.detail}</div>}
      {(t.status === "waiting" || t.status === "active") && (
        <button className="transfer-cancel" aria-label={`Cancel ${t.name}`} onClick={() => onCancel(t)}>
          Cancel
        </button>
      )}
    </li>
  );
}

function RequestDialog({
  request,
  onAnswer,
}: {
  request: IncomingRequest;
  onAnswer: (request: IncomingRequest, accept: boolean, allowFolder?: boolean) => void;
}) {
  const [left, setLeft] = useState(ANSWER_SECONDS);
  const [allowFolder, setAllowFolder] = useState(false);
  const folder = request.files != null;
  useEffect(() => {
    const timer = setInterval(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(timer);
  }, []);
  // Out of time: decline here too (the other side stops waiting anyway).
  useEffect(() => {
    if (left === 0) onAnswer(request, false);
  }, [left, request, onAnswer]);
  const fetch = request.fetch;
  return (
    <div className="backdrop">
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="request-title">
        <h2 id="request-title">{fetch ? "File request" : folder ? "Incoming folder" : "Incoming file"}</h2>
        <p>
          <strong>{request.peer_name}</strong> ({request.peer_ip}){" "}
          {fetch ? "asks for your file" : folder ? "wants to send you the folder" : "wants to send you"}
        </p>
        <p className="file">
          {request.name}{" "}
          <span>
            {folder ? `${plural(request.files ?? 0, "file")}, ` : ""}
            {formatSize(request.size)}
          </span>
        </p>
        {!request.verified && (
          <p className="unverified" role="note">
            Unverified device: it isn't paired, so anyone could be using this name.
          </p>
        )}
        {fetch?.via_assistant && (
          <p className="assistant" role="note">
            An AI assistant on {request.peer_name} asked for this file.
          </p>
        )}
        {fetch && (
          <p className="reason">
            {fetch.reason.trim() ? (
              <>Reason given: “{fetch.reason.trim()}”</>
            ) : (
              "No reason given."
            )}
          </p>
        )}
        {fetch?.grant_folder && (
          <label className="grant">
            <input type="checkbox" checked={allowFolder} onChange={(e) => setAllowFolder(e.target.checked)} />
            Also let {request.peer_name} fetch from {fetch.grant_folder} for 10 minutes without asking
          </label>
        )}
        <p className="countdown">Declines automatically in {left}s</p>
        <div className="actions">
          <button onClick={() => onAnswer(request, false)}>Decline</button>
          <button className="primary" onClick={() => onAnswer(request, true, allowFolder)} autoFocus>
            {fetch ? "Approve" : "Accept"}
          </button>
        </div>
      </div>
    </div>
  );
}
