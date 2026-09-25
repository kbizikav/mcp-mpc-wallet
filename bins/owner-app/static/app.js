// Owner app for the MCP MPC wallet.
//
// Every sensitive action is signed in the browser with a passkey (Touch ID) and verified by the
// judge node. Text coming from the judge or from the agent can be attacker-influenced, so it is
// only ever rendered with textContent, never as HTML.

const RP_ID = "localhost";
const CREDENTIAL_KEY = "mw-passkey-credential-id";
const EXPLORER = "https://sepolia.basescan.org/tx/";

const $ = (id) => document.getElementById(id);

// ---- helpers ---------------------------------------------------------------

function b64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "onclick") node.addEventListener("click", value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

let toastTimer;
function toast(message, kind = "success") {
  const t = $("toast");
  t.textContent = message;
  t.className = `toast ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 6000);
}

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function shortHex(value) {
  return value && value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
}

function time(unix) {
  return new Date(unix * 1000).toLocaleTimeString();
}

async function busy(button, fn) {
  button.disabled = true;
  try {
    await fn();
  } catch (e) {
    toast(e.message || String(e), "error");
  } finally {
    button.disabled = false;
  }
}

// ---- passkey ---------------------------------------------------------------

function credentialId() {
  try {
    return localStorage.getItem(CREDENTIAL_KEY);
  } catch {
    return null;
  }
}

async function createPasskey() {
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { id: RP_ID, name: "MCP MPC Wallet" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "wallet-owner",
        displayName: "Wallet owner",
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      attestation: "none",
    },
  });
  const spki = credential.response.getPublicKey();
  if (!spki) throw new Error("this browser did not return the passkey's public key");
  // Register it with the judge node (signed once by the current passkey).
  await api("/api/passkey/adopt", { credential_id: b64url(credential.rawId), spki: b64url(spki) });
  localStorage.setItem(CREDENTIAL_KEY, b64url(credential.rawId));
  toast("Passkey registered with the judge node.");
}

// Build the operation on the server, sign its challenge with the passkey, and submit.
async function signed(request) {
  const id = credentialId();
  if (!id) throw new Error("Create a passkey on this device first.");
  const { operation, challenge } = await api("/api/challenge", request);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: fromB64url(challenge),
      rpId: RP_ID,
      allowCredentials: [{ type: "public-key", id: fromB64url(id) }],
      userVerification: "required",
    },
  });
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

// ---- status ----------------------------------------------------------------

async function refreshStatus() {
  let s;
  try {
    s = await api("/api/status");
  } catch (e) {
    $("state").textContent = "judge node unreachable";
    return;
  }
  $("wallet").textContent = s.wallet;
  $("balance").textContent = s.balance_eth === null ? "—" : `${Number(s.balance_eth).toFixed(6)} ETH`;
  $("network").textContent = s.chain;
  $("state").textContent = s.frozen ? "Frozen" : "Active";
  $("state").style.color = s.frozen ? "var(--bad)" : "var(--ok)";
  $("policy-version").textContent = s.policy_version ? `Current policy: v${s.policy_version}` : "No policy yet";

  const badges = $("badges");
  badges.replaceChildren(
    s.attested
      ? el("span", { class: "badge ok", title: `PCR0 ${s.pcr0}` }, `✓ Attested Nitro Enclave · PCR0 ${shortHex(s.pcr0)}`)
      : el("span", { class: "badge warn" }, "Judge node not attested (development)"),
    el("span", { class: s.frozen ? "badge bad" : "badge ok" }, s.frozen ? "Frozen" : "Active"),
  );

  const hasLocal = Boolean(credentialId());
  $("passkey-status").textContent = hasLocal
    ? "This device holds the wallet's passkey."
    : s.legacy_passkey
      ? "No passkey on this device yet. Create one to take over from the current passkey."
      : "No passkey on this device. Start mw-owner with --legacy-passkey to register one.";
  $("create-passkey").classList.toggle("hidden", hasLocal || !s.legacy_passkey);
}

// ---- owner view ------------------------------------------------------------

function describeNotice(n) {
  switch (n.kind) {
    case "submitted":
      return ["Transaction sent", el("a", { href: EXPLORER + n.tx_hash, target: "_blank", rel: "noopener" }, shortHex(n.tx_hash))];
    case "signed":
      return ["Signature returned to the agent", shortHex(n.request_id)];
    case "needs_confirmation":
      return ["Needs your approval", n.summary || shortHex(n.request_id)];
    case "rejected":
      return ["Rejected by the judge", shortHex(n.request_id)];
    case "approved_by_user":
      return ["Approved with your passkey", shortHex(n.request_id)];
    case "policy_updated":
      return ["Policy updated", `v${n.version}`];
    case "frozen":
      return ["Wallet frozen", n.reason];
    case "unfrozen":
      return ["Wallet unfrozen", ""];
    case "submission_failed":
      return ["Signing or sending failed", n.error];
    default:
      return [n.kind, ""];
  }
}

function reasonsList(reasons) {
  const useful = (reasons || []).filter((r) => !r.startsWith("model:"));
  if (!useful.length) return null;
  return el("ul", {}, ...useful.slice(0, 4).map((r) => el("li", {}, r)));
}

function renderPending(requests) {
  const list = $("pending");
  if (!requests.length) {
    list.replaceChildren(el("div", { class: "empty" }, "Nothing is waiting for you."));
    return;
  }
  list.replaceChildren(
    ...requests.map((p) => {
      let effects = p.effects;
      try {
        effects = JSON.stringify(JSON.parse(p.effects), null, 2);
      } catch {}
      const approve = el("button", { class: "ok" }, p.approved ? "Approved" : "Approve (Touch ID)");
      approve.disabled = p.approved;
      approve.addEventListener("click", () =>
        busy(approve, async () => {
          await signed({ kind: "approve", request_id: p.request_id });
          toast("Approved. Ask the agent to resume the transaction within 5 minutes.");
          await unlock();
        }),
      );
      const reject = el("button", { class: "danger" }, "Reject");
      reject.addEventListener("click", () =>
        busy(reject, async () => {
          await api("/api/reject", { request_id: p.request_id });
          toast("Rejected.");
          await unlock();
        }),
      );
      return el(
        "div",
        { class: "item" },
        el("div", { class: "item-head" },
          el("span", { class: "item-title" }, p.summary || "Transaction needs your approval"),
          el("span", { class: "muted" }, time(p.created_at))),
        reasonsList(p.reasons),
        effects ? el("details", {}, el("summary", {}, "What this transaction does"), el("pre", {}, effects)) : null,
        el("div", { class: "row" }, el("span", { class: "muted mono" }, shortHex(p.request_id)), el("span", {}, reject, " ", approve)),
      );
    }),
  );
}

function renderActivity(recent) {
  const list = $("activity");
  if (!recent.length) {
    list.replaceChildren(el("div", { class: "empty" }, "No activity yet."));
    return;
  }
  list.replaceChildren(
    ...recent.map(({ at, notice }) => {
      const [title, detail] = describeNotice(notice);
      return el(
        "div",
        { class: "item" },
        el("div", { class: "item-head" },
          el("span", {}, el("span", { class: `kind ${notice.kind}` }, title), " ", detail),
          el("span", { class: "muted" }, time(at))),
        reasonsList(notice.reasons),
      );
    }),
  );
}

async function unlock() {
  const view = await signed({ kind: "view" });
  renderPending(view.requests || []);
  renderActivity(view.recent || []);
  if (view.policy_text && !$("policy").value) $("policy").value = view.policy_text;
  $("owner-body").classList.remove("hidden");
  $("owner-hint").classList.add("hidden");
}

// ---- wiring ----------------------------------------------------------------

function main() {
  if (location.hostname !== RP_ID) $("host-warning").classList.remove("hidden");

  $("create-passkey").addEventListener("click", (e) => busy(e.currentTarget, async () => {
    await createPasskey();
    await refreshStatus();
  }));
  $("unlock").addEventListener("click", (e) => busy(e.currentTarget, unlock));
  $("save-policy").addEventListener("click", (e) => busy(e.currentTarget, async () => {
    const r = await signed({ kind: "set_policy", text: $("policy").value });
    toast(`Policy v${r.version} saved.`);
    await refreshStatus();
  }));
  $("freeze").addEventListener("click", (e) => busy(e.currentTarget, async () => {
    await api("/api/freeze", {});
    toast("Wallet frozen. The agent can no longer move funds.");
    await refreshStatus();
  }));
  $("unfreeze").addEventListener("click", (e) => busy(e.currentTarget, async () => {
    await signed({ kind: "unfreeze" });
    toast("Wallet unfrozen.");
    await refreshStatus();
  }));

  refreshStatus();
  setInterval(refreshStatus, 10000);
}

main();
