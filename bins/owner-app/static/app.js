// Owner app for the MCP MPC wallet.
//
// Every sensitive action is signed in the browser with a passkey (Touch ID) and verified by the
// judge node. Text coming from the judge or from the agent can be attacker-influenced, so it is
// only ever rendered as text, never as HTML.

import {
  $, el, icon, api, busy, toast, shortHex, timeAgo, clockTime, formatEth, addressLink, txLink,
  copyButton, signed, storedCredential, storeCredential, createPasskey, templatePicker, RP_ID,
} from "./ui.js";
import { startSetup, setupPending } from "./setup.js";

const app = {
  status: null,
  view: null, // the unlocked owner view (pending requests, activity, policy)
  unlockedAt: 0,
  page: "overview",
};

const PAGES = [
  { id: "overview", title: "Overview", icon: "grid" },
  { id: "approvals", title: "Approvals", icon: "inbox" },
  { id: "activity", title: "Activity", icon: "pulse" },
  { id: "policy", title: "Policy", icon: "doc" },
  { id: "security", title: "Security", icon: "shield" },
];

// ---- shell -------------------------------------------------------------------------

function renderNav() {
  const pending = app.view ? app.view.requests.filter((r) => !r.approved).length : 0;
  $("nav").replaceChildren(
    ...PAGES.map((p) =>
      el(
        "a",
        {
          href: `#${p.id}`,
          class: app.page === p.id ? "active" : "",
          "aria-current": app.page === p.id ? "page" : null,
        },
        icon(p.icon, 18),
        el("span", {}, p.title),
        p.id === "approvals" && pending ? el("span", { class: "count" }, String(pending)) : null,
      ),
    ),
  );
}

function renderTopbar() {
  const s = app.status;
  const pills = [el("span", { class: "pill" }, el("span", { class: "dot net" }), s.chain)];
  pills.push(
    s.attested
      ? el("span", { class: "pill ok", title: `PCR0 ${s.pcr0}` }, icon("shield", 14), "Verified enclave")
      : el("span", { class: "pill warn" }, icon("alert", 14), "Not attested"),
  );
  pills.push(
    s.frozen
      ? el("span", { class: "pill bad" }, icon("snow", 14), "Frozen")
      : el("span", { class: "pill ok" }, el("span", { class: "dot live" }), "Active"),
  );
  $("topbar-right").replaceChildren(
    ...pills,
    el("span", { class: "wallet-chip" }, el("span", { class: "avatar", style: avatarStyle(s.wallet) }), el("span", { class: "mono" }, shortHex(s.wallet)), copyButton(s.wallet, "")),
  );
}

// A deterministic gradient per address, so wallets are easy to tell apart.
function avatarStyle(address) {
  const h1 = parseInt(address.slice(2, 6), 16) % 360;
  const h2 = parseInt(address.slice(-4), 16) % 360;
  return `background: linear-gradient(135deg, hsl(${h1} 70% 55%), hsl(${h2} 70% 45%))`;
}

function render() {
  if (!app.status) return;
  renderNav();
  renderTopbar();
  const main = $("page");
  main.replaceChildren();
  ({ overview, approvals, activity, policy, security })[app.page](main);
}

function pageHeader(title, subtitle, ...right) {
  return el("div", { class: "page-head" }, el("div", {}, el("h1", {}, title), subtitle ? el("p", { class: "muted" }, subtitle) : null), el("div", { class: "page-actions" }, ...right));
}

function card(attrs, ...children) {
  return el("section", { ...attrs, class: `card ${attrs.class || ""}` }, ...children);
}

// The owner view is signed with the passkey. Until then, those pages show a lock.
function lockedCard(what) {
  const unlock = el("button", { class: "primary" }, icon("fingerprint", 18), el("span", {}, "Unlock with passkey"));
  unlock.addEventListener("click", () => busy(unlock, refreshView));
  return card(
    { class: "locked" },
    el("div", { class: "lock-icon" }, icon("lock", 26)),
    el("h3", {}, `Unlock to see ${what}`),
    el("p", { class: "muted" }, "The judge node only shows details to the wallet's passkey. The agent gets coarse reasons only."),
    unlock,
  );
}

function refreshButton() {
  const b = el("button", { class: "ghost" }, icon("refresh", 16), el("span", {}, app.view ? `Updated ${timeAgo(app.unlockedAt)}` : "Unlock"));
  b.addEventListener("click", () => busy(b, refreshView));
  return b;
}

async function refreshView() {
  const view = await signed(app.status.wallet, { kind: "view" });
  app.view = { requests: view.requests || [], recent: view.recent || [], policy_text: view.policy_text || "" };
  app.unlockedAt = Math.floor(Date.now() / 1000);
  render();
}

// ---- overview ------------------------------------------------------------------------

function overview(main) {
  const s = app.status;
  const pending = app.view ? app.view.requests.filter((r) => !r.approved).length : null;
  main.append(
    pageHeader("Overview", "Your agent proposes. An attested judge decides. You stay in control."),
    el(
      "div",
      { class: "grid-2" },
      card(
        { class: "balance-card" },
        el("div", { class: "label" }, "Balance"),
        el("div", { class: "balance" }, el("span", { class: "num" }, formatEth(s.balance_eth)), el("span", { class: "unit" }, "ETH")),
        el("div", { class: "muted small" }, s.balance_eth === null ? "Set ALCHEMY_API_KEY to show the balance." : `${s.chain} · chain ${s.chain_id}`),
        el("div", { class: "addr-row" }, addressLink(s.wallet), copyButton(s.wallet)),
      ),
      el(
        "div",
        { class: "stat-stack" },
        stat("Pending approvals", pending === null ? "—" : String(pending), "inbox", () => nav("approvals"), pending ? "warn" : ""),
        stat("Policy", s.policy_version ? `v${s.policy_version}` : "None", "doc", () => nav("policy"), s.policy_version ? "" : "warn"),
        stat("Wallet", s.frozen ? "Frozen" : "Active", s.frozen ? "snow" : "check", () => nav("security"), s.frozen ? "bad" : "ok"),
      ),
    ),
    card({}, el("div", { class: "card-head" }, el("h3", {}, "How a transaction is approved")), pipeline(s)),
    card({}, el("div", { class: "card-head" }, el("h3", {}, "2-of-3 key shares"), el("span", { class: "muted small" }, "No complete private key exists anywhere")), sharesDiagram(s)),
  );
  if (!s.policy_version) {
    main.insertBefore(
      el("div", { class: "banner warn" }, icon("alert", 18), el("span", {}, "No policy yet: the judge rejects every proposal."), el("a", { href: "#policy" }, "Set a policy")),
      main.children[1],
    );
  }
}

function stat(label, value, iconName, onclick, tone) {
  return el("button", { class: `stat ${tone || ""}`, type: "button", onclick }, el("span", { class: "stat-icon" }, icon(iconName, 18)), el("span", { class: "stat-body" }, el("span", { class: "label" }, label), el("span", { class: "stat-value" }, value)), icon("arrowRight", 16));
}

function pipeline(s) {
  const node = (iconName, title, sub, tone) => el("div", { class: `pipe-node ${tone || ""}` }, el("div", { class: "pipe-icon" }, icon(iconName, 22)), el("strong", {}, title), el("span", { class: "muted small" }, sub));
  const link = (label) => el("div", { class: "pipe-link" }, el("span", {}, label));
  return el(
    "div",
    { class: "pipeline" },
    node("bot", "AI agent", "Claude Code · MCP"),
    link("proposes"),
    node("laptop", "Signer A", "This Mac"),
    link("mTLS + attestation"),
    node("chip", "Judge B", s.attested ? "Nitro Enclave · verified" : "Development", s.attested ? "ok" : "warn"),
    link("co-signs & broadcasts"),
    node("chain", "Base Sepolia", "Testnet"),
  );
}

function sharesDiagram(s) {
  const tile = (letter, title, where, note, on) => el("div", { class: `share-tile ${on ? "on" : ""}` }, el("div", { class: "share-letter" }, letter), el("div", {}, el("strong", {}, title), el("span", { class: "muted small" }, where), el("span", { class: "tiny" }, note)));
  return el(
    "div",
    { class: "share-row" },
    tile("A", "Signer share", "This Mac", "Used with B for every agent transaction", true),
    tile("B", "Judge share", "Nitro Enclave", s.attested ? "Sealed by KMS to this enclave image" : "Development storage", true),
    tile("C", "Recovery share", "Encrypted on this Mac", s.recovery_share ? "Locked with your passphrase" : "Not in this data directory", s.recovery_share),
  );
}

// ---- approvals -----------------------------------------------------------------------

function parseEffects(text) {
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

function tokenName(t) {
  return t.token_symbol_untrusted ? `${t.token_symbol_untrusted} (unverified symbol)` : `tokens of ${shortHex(t.token)}`;
}

function formatAmount(raw, unlimited) {
  if (unlimited) return "an unlimited amount of";
  return `${raw} units of`;
}

// Turn the judge's decoded effects into short sentences. Everything here comes from the judge's
// own decoding and simulation, not from the agent.
function effectLines(e) {
  const lines = [];
  if (!e) return lines;
  if (e.primary_type_untrusted !== undefined) {
    lines.push(["pen", ["Sign an off-chain message ", el("code", {}, e.primary_type_untrusted || "?"), e.domain_name_untrusted ? [" for ", el("code", {}, e.domain_name_untrusted)] : null]]);
    const g = e.grants;
    if (g) {
      const what = g.unlimited ? "UNLIMITED" : g.amount_raw;
      if (g.kind === "erc2612_permit") lines.push(["alert", ["Grants ", el("strong", { class: "bad-text" }, `${what} allowance`), " of ", g.token ? addressLink(g.token) : "a token", " to ", addressLink(g.spender)], "bad"]);
      else lines.push(["alert", ["Grants Permit2 ", el("strong", { class: "bad-text" }, what), " of ", addressLink(g.token), " to ", addressLink(g.spender)], "bad"]);
    } else {
      lines.push(["check", "Grants no known token rights", "ok"]);
    }
    if (e.verifying_contract) lines.push(["doc", ["Verifying contract ", addressLink(e.verifying_contract)]]);
    return lines;
  }
  const sim = e.simulation || {};
  for (const t of sim.outgoing || []) {
    lines.push(["send", ["Send ", el("strong", {}, t.amount_eth !== null && t.amount_eth !== undefined ? `${formatEth(t.amount_eth, 18)} ETH` : `${t.amount_raw} ${tokenName(t)}`), " to ", addressLink(t.counterparty)]]);
  }
  for (const t of sim.incoming || []) {
    lines.push(["check", ["Receive ", el("strong", {}, t.amount_eth ? `${formatEth(t.amount_eth, 18)} ETH` : `${t.amount_raw} ${tokenName(t)}`), " from ", addressLink(t.counterparty)], "ok"]);
  }
  for (const a of sim.allowance_changes || []) {
    lines.push(["alert", ["Allow ", addressLink(a.spender), " to spend ", el("strong", { class: a.unlimited ? "bad-text" : "" }, formatAmount(a.amount_raw, a.unlimited)), " ", addressLink(a.token)], "bad"]);
  }
  const call = e.decoded_call;
  if (call && !(sim.allowance_changes || []).length) {
    if (call.kind === "erc20_approve" || call.kind === "erc20_increase_allowance")
      lines.push(["alert", ["Approve ", addressLink(call.spender), " for ", el("strong", { class: call.unlimited ? "bad-text" : "" }, call.unlimited ? "an unlimited amount" : call.amount_raw || call.added_raw), " of ", addressLink(call.token)], "bad"]);
    if (call.kind === "set_approval_for_all" && call.approved)
      lines.push(["alert", ["Give ", addressLink(call.operator), " control of ", el("strong", { class: "bad-text" }, "all NFTs"), " in ", addressLink(call.collection)], "bad"]);
  }
  if (e.contract_creation) lines.push(["alert", "Deploy a new contract", "bad"]);
  else if (e.selector && !call) lines.push(["doc", ["Call ", addressLink(e.to), " with unknown function ", el("code", {}, e.selector)]]);
  if (!lines.length && e.to) lines.push(["send", ["Send ", el("strong", {}, `${formatEth(e.native_value_eth, 18)} ETH`), " to ", addressLink(e.to)]]);
  if (sim.unrelated_transfers) lines.push(["alert", `${sim.unrelated_transfers} other asset movement(s) not involving this wallet`, "warn"]);
  if (e.max_gas_cost_eth) lines.push(["clock", ["Max network fee ", el("span", { class: "num" }, `${formatEth(e.max_gas_cost_eth, 8)} ETH`)], "muted"]);
  return lines;
}

function effectsList(effects) {
  const lines = effectLines(effects);
  if (!lines.length) return null;
  return el("ul", { class: "effects" }, lines.map(([i, content, tone]) => el("li", { class: tone || "" }, icon(i, 16), el("span", {}, content))));
}

function reasonsList(reasons) {
  const useful = (reasons || []).filter((r) => !r.startsWith("model:"));
  if (!useful.length) return null;
  return el("div", { class: "reasons" }, el("div", { class: "label" }, "Why the judge asks you"), el("ul", {}, useful.slice(0, 5).map((r) => el("li", {}, r))));
}

function approvals(main) {
  main.append(pageHeader("Approvals", "Requests the judge would not decide alone. Approve with your passkey, then ask the agent to resume within 5 minutes.", refreshButton()));
  if (!app.view) return main.append(lockedCard("pending requests"));
  const requests = app.view.requests;
  if (!requests.length) {
    return main.append(card({ class: "empty" }, icon("check", 28), el("h3", {}, "All clear"), el("p", { class: "muted" }, "Nothing is waiting for you.")));
  }
  for (const p of requests) {
    const effects = parseEffects(p.effects);
    const approve = el("button", { class: "primary" }, icon("fingerprint", 18), el("span", {}, p.approved ? "Approved" : "Approve"));
    approve.disabled = p.approved;
    approve.addEventListener("click", () =>
      busy(approve, async () => {
        await signed(app.status.wallet, { kind: "approve", request_id: p.request_id });
        toast("Approved. Ask the agent to resume it within 5 minutes.");
        await refreshView();
      }),
    );
    const reject = el("button", { class: "danger-ghost" }, icon("x", 16), el("span", {}, "Reject"));
    reject.addEventListener("click", () =>
      busy(reject, async () => {
        await api("/api/reject", { request_id: p.request_id });
        toast("Rejected.");
        await refreshView();
      }),
    );
    main.append(
      card(
        { class: `request ${p.approved ? "approved" : ""}` },
        el(
          "div",
          { class: "request-head" },
          el("span", { class: `tag ${p.approved ? "ok" : "warn"}` }, p.approved ? "Approved — waiting for the agent" : "Needs your approval"),
          el("span", { class: "muted small", title: new Date(p.created_at * 1000).toString() }, timeAgo(p.created_at)),
        ),
        el("h3", {}, p.summary || "Review this request"),
        effectsList(effects),
        reasonsList(p.reasons),
        el("details", {}, el("summary", {}, "Decoded & simulated by the enclave (raw)"), el("pre", { class: "code" }, effects ? JSON.stringify(effects, null, 2) : p.effects)),
        el("div", { class: "request-foot" }, el("span", { class: "mono muted small", title: p.request_id }, `Request ${shortHex(p.request_id, 10, 6)}`), el("div", { class: "btn-row" }, p.approved ? null : reject, approve)),
      ),
    );
  }
}

// ---- activity ------------------------------------------------------------------------

const NOTICE = {
  submitted: ["send", "ok", "Transaction sent", (n) => txLink(n.tx_hash)],
  signed: ["pen", "ok", "Signature returned to the agent", (n) => el("span", { class: "mono" }, shortHex(n.request_id, 10, 6))],
  needs_confirmation: ["inbox", "warn", "Waiting for your approval", (n) => n.summary || el("span", { class: "mono" }, shortHex(n.request_id, 10, 6))],
  rejected: ["x", "bad", "Rejected by the judge", (n) => el("span", { class: "mono" }, shortHex(n.request_id, 10, 6))],
  approved_by_user: ["fingerprint", "accent", "You approved", (n) => el("span", { class: "mono" }, shortHex(n.request_id, 10, 6))],
  policy_updated: ["doc", "accent", "Policy updated", (n) => `v${n.version}`],
  frozen: ["snow", "bad", "Wallet frozen", (n) => n.reason],
  unfrozen: ["sun", "ok", "Wallet unfrozen", () => ""],
  submission_failed: ["alert", "bad", "Signing or sending failed", (n) => n.error],
};

function activity(main) {
  main.append(pageHeader("Activity", "Everything the judge decided for this wallet, with the reasons only you can see.", refreshButton()));
  if (!app.view) return main.append(lockedCard("the activity"));
  const recent = app.view.recent;
  if (!recent.length) return main.append(card({ class: "empty" }, icon("pulse", 28), el("h3", {}, "No activity yet"), el("p", { class: "muted" }, "Ask your agent to do something.")));
  main.append(
    card(
      { class: "timeline-card" },
      el(
        "ol",
        { class: "timeline" },
        recent.map(({ at, notice }) => {
          const [iconName, tone, title, detail] = NOTICE[notice.kind] || ["doc", "", notice.kind, () => ""];
          const reasons = (notice.reasons || []).filter((r) => !r.startsWith("model:"));
          return el(
            "li",
            { class: tone },
            el("span", { class: "t-icon" }, icon(iconName, 16)),
            el(
              "div",
              { class: "t-body" },
              el("div", { class: "t-head" }, el("strong", {}, title), el("span", { class: "muted small", title: new Date(at * 1000).toString() }, clockTime(at))),
              el("div", { class: "t-detail" }, detail(notice)),
              reasons.length ? el("details", {}, el("summary", {}, `Judge's reasons (${reasons.length})`), el("ul", {}, reasons.map((r) => el("li", {}, r)))) : null,
            ),
          );
        }),
      ),
    ),
  );
}

// ---- policy ------------------------------------------------------------------------------

function policy(main) {
  const s = app.status;
  main.append(pageHeader("Policy", "Plain-language rules. The judge checks what each proposal really does against them.", s.policy_version ? el("span", { class: "tag accent" }, `Current: v${s.policy_version}`) : el("span", { class: "tag warn" }, "No policy")));
  const text = el("textarea", { rows: "9", spellcheck: "false", placeholder: app.view ? "Describe what the agent may do…" : "Unlock to load the current policy, or write a new one." });
  text.value = app.view ? app.view.policy_text : "";
  const save = el("button", { class: "primary" }, icon("fingerprint", 18), el("span", {}, "Sign & save"));
  save.addEventListener("click", () =>
    busy(save, async () => {
      const r = await signed(s.wallet, { kind: "set_policy", text: text.value });
      toast(`Policy v${r.version} saved.`);
      if (app.view) app.view.policy_text = text.value.trim();
      await refreshStatus();
    }),
  );
  const load = el("button", { class: "ghost" }, icon("unlock", 16), el("span", {}, "Load current"));
  load.addEventListener("click", () => busy(load, refreshView));
  main.append(
    card(
      { class: "policy-card" },
      el("div", { class: "label" }, "Templates"),
      templatePicker((t) => (text.value = t)),
      text,
      el("div", { class: "policy-foot" }, el("span", { class: "fine" }, icon("lock", 14), " Only your passkey can change this. The agent has no tool for it."), el("div", { class: "btn-row" }, app.view ? null : load, save)),
    ),
  );
}

// ---- security ------------------------------------------------------------------------------

function security(main) {
  const s = app.status;
  const freeze = el("button", { class: "danger" }, icon("snow", 16), el("span", {}, "Freeze now"));
  freeze.addEventListener("click", () =>
    busy(freeze, async () => {
      await api("/api/freeze", {});
      toast("Wallet frozen. The agent can no longer move funds.");
      await refreshStatus();
    }),
  );
  const unfreeze = el("button", { class: "primary" }, icon("fingerprint", 18), el("span", {}, "Unfreeze"));
  unfreeze.addEventListener("click", () =>
    busy(unfreeze, async () => {
      await signed(s.wallet, { kind: "unfreeze" });
      toast("Wallet unfrozen.");
      await refreshStatus();
    }),
  );

  const hasLocal = Boolean(storedCredential(s.wallet));
  const adopt = el("button", { class: "primary" }, icon("fingerprint", 18), el("span", {}, "Create passkey on this device"));
  adopt.addEventListener("click", () =>
    busy(adopt, async () => {
      const passkey = await createPasskey("MPC wallet owner");
      await api("/api/passkey/adopt", passkey);
      storeCredential(s.wallet, passkey.credential_id);
      toast("Passkey registered with the judge node.");
      render();
    }),
  );

  main.append(
    pageHeader("Security", "Emergency controls and what protects your keys."),
    el(
      "div",
      { class: "grid-2" },
      card(
        { class: s.frozen ? "frozen-card" : "" },
        el("div", { class: "card-head" }, el("h3", {}, icon(s.frozen ? "snow" : "sun", 18), s.frozen ? "Wallet is frozen" : "Emergency freeze")),
        el("p", { class: "muted" }, s.frozen ? "The judge refuses every proposal. Unfreezing needs your passkey." : "One click stops the agent immediately. No signature needed — unfreezing needs your passkey."),
        el("div", { class: "btn-row" }, s.frozen ? unfreeze : freeze),
      ),
      card(
        {},
        el("div", { class: "card-head" }, el("h3", {}, icon("fingerprint", 18), "Passkey")),
        el("p", { class: "muted" }, s.passkey_registered ? (hasLocal ? "This device holds the wallet's passkey." : "A passkey is registered. This browser has not used it yet — it will ask when you sign.") : "No passkey is registered for this wallet."),
        el("dl", { class: "kv" }, el("dt", {}, "Relying party"), el("dd", { class: "mono" }, RP_ID), el("dt", {}, "Verified by"), el("dd", {}, "Judge node B (inside the enclave)")),
        s.legacy_passkey ? el("div", { class: "btn-row" }, adopt) : null,
      ),
      card(
        {},
        el("div", { class: "card-head" }, el("h3", {}, icon("vault", 18), "Recovery share C")),
        el("p", { class: "muted" }, s.recovery_share ? "Encrypted with your recovery passphrase (age + scrypt). With share C and the judge node you can move the funds if this Mac is lost — still only after the owner's passkey approves." : "No encrypted recovery share in this data directory."),
      ),
      card(
        {},
        el("div", { class: "card-head" }, el("h3", {}, icon("shield", 18), "Judge node attestation")),
        s.attested
          ? el("p", { class: "muted" }, "Before every session, the signer and this app check an AWS-signed attestation document bound to the TLS certificate, and compare the enclave image measurement.")
          : el("p", { class: "warn-text" }, "This judge node is not attested (development mode)."),
        el("dl", { class: "kv" }, el("dt", {}, "Endpoint"), el("dd", { class: "mono" }, s.node_b), s.pcr0 ? [el("dt", {}, "PCR0"), el("dd", { class: "mono wrap" }, s.pcr0)] : null),
      ),
    ),
  );
}

// ---- wiring --------------------------------------------------------------------------------

function nav(page) {
  location.hash = page;
}

function onHash() {
  const page = location.hash.slice(1);
  app.page = PAGES.some((p) => p.id === page) ? page : "overview";
  render();
  $("page").focus({ preventScroll: true });
}

async function refreshStatus() {
  try {
    app.status = await api("/api/status");
    $("offline").classList.add("hidden");
  } catch (e) {
    $("offline").classList.remove("hidden");
    $("offline").lastChild.textContent = `Judge node unreachable: ${e.message}`;
    return;
  }
  render();
}

function startDashboard() {
  document.body.dataset.mode = "app";
  window.addEventListener("hashchange", onHash);
  app.page = PAGES.some((p) => `#${p.id}` === location.hash) ? location.hash.slice(1) : "overview";
  refreshStatus();
  setInterval(refreshStatus, 15000);
}

async function main() {
  if (location.hostname !== RP_ID) $("host-warning").classList.remove("hidden");
  let state;
  try {
    state = await api("/api/setup/state");
  } catch (e) {
    document.body.dataset.mode = "app";
    $("offline").classList.remove("hidden");
    $("offline").lastChild.textContent = `Cannot reach mw-owner: ${e.message}`;
    return;
  }
  if (!state.wallet || setupPending()) startSetup(state, startDashboard);
  else startDashboard();
}

main();
