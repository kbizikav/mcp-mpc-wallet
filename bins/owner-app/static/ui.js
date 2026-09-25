// Shared helpers for the owner app: DOM building, icons, API calls, and passkeys.
//
// Text that comes from the judge node or the agent can be attacker-influenced. It is only ever
// inserted with text nodes (see `el`), never as HTML.

export const RP_ID = "localhost";
export const EXPLORER = "https://sepolia.basescan.org";

export const $ = (id) => document.getElementById(id);

// ---- DOM -------------------------------------------------------------------

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(node, child);
    else node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

const SVG_NS = "http://www.w3.org/2000/svg";

// Stroke icons (24×24). Only static path data, never user input.
const ICONS = {
  shield: ["M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z", "M9 12l2 2 4-4"],
  key: ["M15 7a4 4 0 1 1-3.9 5H3v3h3v3h3v-3h2.1A4 4 0 0 1 15 7z", "M16 10h.01"],
  fingerprint: [
    "M12 11v3a8 8 0 0 1-1.5 4.7",
    "M8 9.5A4 4 0 0 1 16 10v2.5",
    "M5 8a8 8 0 0 1 14 3.5V13",
    "M8.5 13v1a11 11 0 0 1-1.3 5",
    "M15.8 15.5a14 14 0 0 1-1 4",
  ],
  lock: ["M6 11h12v10H6z", "M8 11V7a4 4 0 0 1 8 0v4"],
  unlock: ["M6 11h12v10H6z", "M8 11V7a4 4 0 0 1 7.5-2"],
  send: ["M4 12l16-8-6 16-2.5-6.5z", "M11.5 13.5L20 4"],
  check: ["M5 12.5l4.5 4.5L19 7.5"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  alert: ["M12 3l10 18H2z", "M12 10v4", "M12 17.5h.01"],
  clock: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M12 7v5l3 2"],
  snow: ["M12 2v20", "M3.3 7l17.4 10", "M3.3 17L20.7 7", "M9 4l3 2 3-2", "M9 20l3-2 3 2"],
  sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", "M12 2v2", "M12 20v2", "M4.9 4.9l1.4 1.4", "M17.7 17.7l1.4 1.4", "M2 12h2", "M20 12h2", "M4.9 19.1l1.4-1.4", "M17.7 6.3l1.4-1.4"],
  doc: ["M6 3h8l4 4v14H6z", "M14 3v4h4", "M9 12h6", "M9 16h6"],
  pen: ["M4 20l4-1 11-11-3-3L5 16z", "M14 6l3 3"],
  grid: ["M4 4h7v7H4z", "M13 4h7v7h-7z", "M4 13h7v7H4z", "M13 13h7v7h-7z"],
  inbox: ["M3 13l3-8h12l3 8v6H3z", "M3 13h5l1 2h6l1-2h5"],
  pulse: ["M3 12h4l3-7 4 14 3-7h4"],
  copy: ["M9 9h11v11H9z", "M5 15V4h11"],
  external: ["M14 4h6v6", "M20 4l-9 9", "M18 14v6H4V6h6"],
  bot: ["M6 8h12v10H6z", "M12 4v4", "M9 13h.01", "M15 13h.01", "M3 12v3", "M21 12v3"],
  laptop: ["M5 5h14v10H5z", "M2 19h20"],
  chip: ["M7 7h10v10H7z", "M10 10h4v4h-4z", "M9 3v4", "M15 3v4", "M9 17v4", "M15 17v4", "M3 9h4", "M3 15h4", "M17 9h4", "M17 15h4"],
  chain: ["M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1", "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"],
  vault: ["M4 4h16v16H4z", "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z", "M12 9V7", "M15 12h2"],
  refresh: ["M20 11a8 8 0 0 0-14.9-3M4 5v3h3", "M4 13a8 8 0 0 0 14.9 3M20 19v-3h-3"],
  sparkle: ["M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z", "M19 17l.7 2 2 .7-2 .7-.7 2-.7-2-2-.7 2-.7z"],
  arrowRight: ["M5 12h14", "M13 6l6 6-6 6"],
  eye: ["M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z", "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"],
};

export function icon(name, size = 18) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.classList.add("icon");
  for (const d of ICONS[name] || []) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

// ---- formatting --------------------------------------------------------------

export function shortHex(value, head = 6, tail = 4) {
  if (!value || value.length <= head + tail + 3) return value || "";
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function timeAgo(unix) {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - unix));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return new Date(unix * 1000).toLocaleDateString();
}

export function clockTime(unix) {
  return new Date(unix * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function formatEth(value, digits = 6) {
  if (value === null || value === undefined || value === "") return "—";
  const n = Number(value);
  if (!Number.isFinite(n)) return String(value);
  return n.toLocaleString("en-US", { minimumFractionDigits: 0, maximumFractionDigits: digits });
}

export function addressLink(address) {
  return el(
    "a",
    { class: "mono addr", href: `${EXPLORER}/address/${address}`, target: "_blank", rel: "noopener", title: address },
    shortHex(address),
  );
}

export function txLink(hash) {
  return el(
    "a",
    { class: "mono addr", href: `${EXPLORER}/tx/${hash}`, target: "_blank", rel: "noopener", title: hash },
    shortHex(hash, 10, 6),
    icon("external", 13),
  );
}

// ---- feedback ----------------------------------------------------------------

let toastTimer;
export function toast(message, kind = "success") {
  const t = $("toast");
  t.replaceChildren(icon(kind === "error" ? "alert" : "check", 16), el("span", {}, message));
  t.className = `toast ${kind} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 6000);
}

export async function busy(button, fn) {
  button.disabled = true;
  button.classList.add("loading");
  try {
    return await fn();
  } catch (e) {
    if (e && e.name === "NotAllowedError") toast("Passkey prompt was cancelled.", "error");
    else if (e && e.cancelled) {
      // closed the confirmation dialog
    } else toast((e && e.message) || String(e), "error");
  } finally {
    button.disabled = false;
    button.classList.remove("loading");
  }
}

export async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = el("textarea", {}, text);
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  if (button) {
    const before = button.textContent;
    button.classList.add("copied");
    button.lastChild.textContent = "Copied";
    setTimeout(() => {
      button.classList.remove("copied");
      button.lastChild.textContent = before;
    }, 1500);
  }
}

export function copyButton(text, label = "Copy") {
  const button = el("button", { class: "ghost small", type: "button" }, icon("copy", 14), el("span", {}, label));
  button.addEventListener("click", () => copyText(text, button));
  return button;
}

// ---- API ---------------------------------------------------------------------

export async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

// ---- passkeys ----------------------------------------------------------------

export function b64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

const LEGACY_KEY = "mw-passkey-credential-id";
const walletKey = (wallet) => `mw-passkey:${wallet.toLowerCase()}`;

export function storedCredential(wallet) {
  try {
    return localStorage.getItem(walletKey(wallet)) || localStorage.getItem(LEGACY_KEY);
  } catch {
    return null;
  }
}

export function storeCredential(wallet, credentialId) {
  try {
    localStorage.setItem(walletKey(wallet), credentialId);
  } catch {
    // Without storage the browser still offers the passkey (it is discoverable).
  }
}

// Create a passkey on this device. Returns the values the judge node registers.
export async function createPasskey(label) {
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { id: RP_ID, name: "MCP MPC Wallet" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: label,
        displayName: label,
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      attestation: "none",
    },
  });
  const spki = credential.response.getPublicKey && credential.response.getPublicKey();
  if (!spki) throw new Error("This browser did not return the passkey's public key.");
  return { credential_id: b64url(credential.rawId), spki: b64url(spki) };
}

// ---- signing confirmation -----------------------------------------------------

// Describe the operation the server built, so the owner sees what the passkey signs.
function describeOperation(op) {
  const rows = [["Wallet", el("span", { class: "mono" }, op.wallet || (op.policy && op.policy.wallet) || "")]];
  switch (op.op) {
    case "set_policy":
      return {
        title: `Save policy v${op.policy.version}`,
        lead: "The judge node will check every future proposal against this text.",
        rows,
        body: el("pre", { class: "quote" }, op.policy.text),
      };
    case "approve_request":
      return {
        title: "Approve this request",
        lead: "The judge node co-signs this exact request once. The agent must resume it within 5 minutes.",
        rows: [...rows, ["Request", el("span", { class: "mono" }, shortHex(op.request_id, 10, 8))]],
      };
    case "unfreeze":
      return {
        title: "Unfreeze the wallet",
        lead: "The agent can propose transactions again.",
        rows: [...rows, ["Freeze epoch", String(op.freeze_epoch)]],
      };
    case "list_pending":
      return {
        title: "Unlock the owner view",
        lead: "Read-only. Shows pending requests, the judge's reasons, and your policy.",
        rows,
      };
    default:
      return { title: op.op || "Sign", lead: "", rows };
  }
}

// Ask the server to build the operation, show it, and sign its challenge with the passkey.
export async function signed(wallet, request) {
  const { operation, challenge } = await api("/api/challenge", request);
  const info = describeOperation(operation);
  const assertion = await confirmAndSign(info, async () => {
    const id = storedCredential(wallet);
    return navigator.credentials.get({
      publicKey: {
        challenge: fromB64url(challenge),
        rpId: RP_ID,
        allowCredentials: id ? [{ type: "public-key", id: fromB64url(id) }] : [],
        userVerification: "required",
      },
    });
  });
  storeCredential(wallet, b64url(assertion.rawId));
  const r = assertion.response;
  return api("/api/submit", {
    operation,
    assertion: {
      credential_id: b64url(assertion.rawId),
      authenticator_data: b64url(r.authenticatorData),
      client_data_json: b64url(r.clientDataJSON),
      signature: b64url(r.signature),
    },
  });
}

// A modal that shows what is about to be signed. The passkey prompt starts from the button click,
// so the browser sees a user gesture.
function confirmAndSign(info, sign) {
  return new Promise((resolve, reject) => {
    const root = $("modal-root");
    const cancel = el("button", { class: "ghost", type: "button" }, "Cancel");
    const go = el("button", { class: "primary", type: "button" }, icon("fingerprint", 18), el("span", {}, "Sign with passkey"));
    const close = (value, error) => {
      root.replaceChildren();
      root.classList.remove("open");
      document.removeEventListener("keydown", onKey);
      if (error) reject(error);
      else resolve(value);
    };
    const onKey = (e) => {
      if (e.key === "Escape" && !go.disabled) close(null, Object.assign(new Error("cancelled"), { cancelled: true }));
    };
    cancel.addEventListener("click", () => close(null, Object.assign(new Error("cancelled"), { cancelled: true })));
    go.addEventListener("click", async () => {
      go.disabled = true;
      cancel.disabled = true;
      go.lastChild.textContent = "Waiting for Touch ID…";
      try {
        close(await sign());
      } catch (e) {
        close(null, e);
      }
    });
    document.addEventListener("keydown", onKey);
    root.replaceChildren(
      el(
        "div",
        { class: "modal", role: "dialog", "aria-modal": "true" },
        el("div", { class: "modal-icon" }, icon("fingerprint", 28)),
        el("div", { class: "eyebrow" }, "You are signing"),
        el("h3", {}, info.title),
        info.lead ? el("p", { class: "muted" }, info.lead) : null,
        el("dl", { class: "kv" }, info.rows.map(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
        info.body || null,
        el("p", { class: "fine" }, icon("shield", 14), " Verified by the judge node inside the Nitro Enclave, not by this app."),
        el("div", { class: "modal-actions" }, cancel, go),
      ),
    );
    root.classList.add("open");
    go.focus();
  });
}

// ---- policy templates ----------------------------------------------------------

export const POLICY_TEMPLATES = [
  {
    name: "Demo budget",
    text:
      "Plain ETH transfers of at most 0.0001 ETH per transaction to any address are allowed without asking.\n" +
      "Plain ETH transfers above 0.0001 ETH and up to 0.0003 ETH need the owner's confirmation.\n" +
      "Everything else must be rejected: larger transfers, token approvals, allowances or permits, and any smart contract call.",
  },
  {
    name: "Tips only",
    text:
      "Plain ETH transfers of at most 0.00005 ETH are allowed without asking.\n" +
      "Anything else needs the owner's confirmation. Token approvals, allowances and permits must always be rejected.",
  },
  {
    name: "Ask me first",
    text:
      "Every transaction and every signature needs the owner's confirmation.\n" +
      "Token approvals, allowances and permits for an unlimited amount must be rejected.",
  },
  {
    name: "Login signatures",
    text:
      "Plain ETH transfers of at most 0.0001 ETH are allowed without asking.\n" +
      "Sign-in messages (EIP-712 login or SIWE-style messages that grant no token rights) are allowed.\n" +
      "Anything that grants token rights (approve, permit, Permit2) must be rejected. Everything else needs the owner's confirmation.",
  },
];

export function templatePicker(onPick) {
  return el(
    "div",
    { class: "chips" },
    POLICY_TEMPLATES.map((t) => el("button", { class: "chip", type: "button", onclick: () => onPick(t.text) }, icon("sparkle", 14), t.name)),
  );
}
