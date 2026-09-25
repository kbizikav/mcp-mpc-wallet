// First-run setup: verify the judge node, create a passkey, choose a recovery passphrase,
// generate the 2-of-3 key shares, connect Claude Code, and sign the first policy.

import {
  $, el, icon, api, busy, toast, shortHex, copyButton, createPasskey, storeCredential, signed,
  templatePicker, POLICY_TEMPLATES,
} from "./ui.js";

const RESUME_KEY = "mw-setup-step";

const STEPS = [
  { id: "judge", title: "Verify the judge node", icon: "shield" },
  { id: "passkey", title: "Create your passkey", icon: "fingerprint" },
  { id: "passphrase", title: "Recovery passphrase", icon: "vault" },
  { id: "keygen", title: "Generate key shares", icon: "key" },
  { id: "connect", title: "Connect Claude Code", icon: "bot" },
  { id: "policy", title: "Set your first policy", icon: "doc" },
];

const KEYGEN_STEPS = [
  { id: "generating_primes", title: "Generating safe primes", detail: "On this Mac, for shares A and C" },
  { id: "distributed_keygen", title: "Distributed key generation", detail: "A, B and C each get a share. No one ever holds the whole key." },
  { id: "aux_info", title: "Auxiliary information", detail: "Paillier keys and proofs for threshold signing" },
  { id: "sealing", title: "Sealing share B", detail: "The enclave seals it with KMS, bound to its PCR0" },
  { id: "done", title: "Wallet ready", detail: "" },
];

const wizard = {
  step: 0,
  state: null, // /api/setup/state
  passkey: null, // {credential_id, spki}
  passphrase: "",
  wallet: null,
  onFinish: null,
};

function remember(step) {
  try {
    if (step === null) sessionStorage.removeItem(RESUME_KEY);
    else sessionStorage.setItem(RESUME_KEY, String(step));
  } catch {}
}

// Called when mw-owner has no wallet, or when setup finished in this tab but was not completed.
export function setupPending() {
  try {
    return sessionStorage.getItem(RESUME_KEY) !== null;
  } catch {
    return false;
  }
}

export async function startSetup(setupState, onFinish) {
  wizard.state = setupState;
  wizard.onFinish = onFinish;
  wizard.wallet = setupState.wallet;
  document.body.dataset.mode = "setup";
  let resume = 0;
  if (setupState.job && setupState.job.running) resume = 3;
  else if (setupState.wallet) {
    try {
      resume = Math.max(4, Number(sessionStorage.getItem(RESUME_KEY) || 4));
    } catch {
      resume = 4;
    }
  }
  go(resume);
}

function go(step) {
  wizard.step = step;
  if (step >= 4) remember(step);
  renderRail();
  const body = $("setup-body");
  body.replaceChildren();
  const view = [judgeStep, passkeyStep, passphraseStep, keygenStep, connectStep, policyStep][step];
  view(body);
  body.querySelector("button.primary, input")?.focus();
}

function renderRail() {
  $("setup-rail").replaceChildren(
    ...STEPS.map((s, i) =>
      el(
        "li",
        { class: i < wizard.step ? "done" : i === wizard.step ? "current" : "" },
        el("span", { class: "rail-dot" }, i < wizard.step ? icon("check", 14) : String(i + 1)),
        el("span", {}, s.title),
      ),
    ),
  );
}

function stepHeader(index, lead) {
  const s = STEPS[index];
  return [
    el("div", { class: "eyebrow" }, `Step ${index + 1} of ${STEPS.length}`),
    el("h2", {}, icon(s.icon, 24), s.title),
    el("p", { class: "lead" }, lead),
  ];
}

function actions(...buttons) {
  return el("div", { class: "actions" }, ...buttons);
}

// ---- 1. judge node -------------------------------------------------------------

function judgeStep(body) {
  const s = wizard.state;
  const next = el("button", { class: "primary" }, el("span", {}, "Continue"), icon("arrowRight", 16));
  next.addEventListener("click", () => go(1));
  const retry = el("button", { class: "ghost" }, icon("refresh", 16), el("span", {}, "Check again"));
  retry.addEventListener("click", () =>
    busy(retry, async () => {
      wizard.state = await api("/api/setup/state");
      go(0);
    }),
  );

  let verdict;
  if (!s.judge_reachable) {
    verdict = el(
      "div",
      { class: "verdict bad" },
      icon("alert", 22),
      el("div", {}, el("strong", {}, "Cannot reach the judge node"), el("p", { class: "mono small" }, s.judge_error || "")),
    );
  } else if (s.attested) {
    verdict = el(
      "div",
      { class: "verdict ok" },
      icon("shield", 22),
      el(
        "div",
        {},
        el("strong", {}, "Verified AWS Nitro Enclave"),
        el("p", {}, "The attestation document is signed by AWS, bound to this TLS session, and its image measurement matches."),
        el("div", { class: "pcr" }, el("span", { class: "label" }, "PCR0"), el("code", {}, s.pcr0)),
      ),
    );
  } else {
    verdict = el(
      "div",
      { class: "verdict warn" },
      icon("alert", 22),
      el("div", {}, el("strong", {}, "Development judge node"), el("p", {}, "Not attested. Start mw-owner with --expected-pcr0 to require a verified enclave.")),
    );
  }

  body.append(
    ...stepHeader(0, "Your agent's transactions are judged by node B. Before trusting it with a key share, this app checks what code it runs."),
    el("div", { class: "facts" }, el("div", {}, el("span", { class: "label" }, "Judge node"), el("span", { class: "mono" }, s.node_b))),
    verdict,
    actions(retry, s.judge_reachable ? next : null),
  );
}

// ---- 2. passkey -------------------------------------------------------------------

function passkeyStep(body) {
  const create = el("button", { class: "primary" }, icon("fingerprint", 18), el("span", {}, "Create passkey with Touch ID"));
  const next = el("button", { class: "primary" }, el("span", {}, "Continue"), icon("arrowRight", 16));
  next.addEventListener("click", () => go(2));
  const status = el("div", {});
  const render = () => {
    status.replaceChildren(
      wizard.passkey
        ? el("div", { class: "verdict ok" }, icon("check", 22), el("div", {}, el("strong", {}, "Passkey created"), el("p", { class: "mono small" }, `Credential ${shortHex(wizard.passkey.credential_id, 10, 6)}`)))
        : null,
    );
    create.classList.toggle("hidden", Boolean(wizard.passkey));
    next.classList.toggle("hidden", !wizard.passkey);
  };
  create.addEventListener("click", () =>
    busy(create, async () => {
      const date = new Date().toISOString().slice(0, 10);
      wizard.passkey = await createPasskey(`MPC wallet ${date}`);
      render();
      next.focus();
    }),
  );
  const back = el("button", { class: "ghost" }, "Back");
  back.addEventListener("click", () => go(0));
  body.append(
    ...stepHeader(1, "The passkey is how you approve risky transactions, change the policy, and unfreeze the wallet. The judge node accepts nothing else."),
    el(
      "ul",
      { class: "points" },
      el("li", {}, icon("lock", 16), "The private key stays in this device's Secure Enclave."),
      el("li", {}, icon("shield", 16), "It is registered inside the attested enclave, over the verified connection."),
      el("li", {}, icon("bot", 16), "The agent has no tool that can use it."),
    ),
    status,
    actions(back, create, next),
  );
  render();
}

// ---- 3. passphrase ------------------------------------------------------------------

function strength(text) {
  if (!text) return { score: 0, label: "" };
  let pool = 0;
  if (/[a-z]/.test(text)) pool += 26;
  if (/[A-Z]/.test(text)) pool += 26;
  if (/[0-9]/.test(text)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(text)) pool += 33;
  const unique = new Set(text).size;
  const bits = Math.min(text.length, unique * 2) * Math.log2(Math.max(pool, 2));
  if (bits < 40) return { score: 1, label: "Weak" };
  if (bits < 60) return { score: 2, label: "Fair" };
  if (bits < 80) return { score: 3, label: "Good" };
  return { score: 4, label: "Strong" };
}

function passphraseStep(body) {
  const first = el("input", { type: "password", autocomplete: "new-password", placeholder: "At least 12 characters", id: "pp1" });
  const second = el("input", { type: "password", autocomplete: "new-password", placeholder: "Type it again", id: "pp2" });
  const meter = el("div", { class: "meter" }, el("span", {}), el("span", {}), el("span", {}), el("span", {}));
  const meterLabel = el("span", { class: "meter-label" }, "");
  const hint = el("p", { class: "hint" }, "");
  const next = el("button", { class: "primary" }, el("span", {}, "Continue"), icon("arrowRight", 16));
  const back = el("button", { class: "ghost" }, "Back");
  back.addEventListener("click", () => go(1));

  const check = () => {
    const a = first.value;
    const b = second.value;
    const s = strength(a);
    meter.dataset.score = s.score;
    meterLabel.textContent = s.label;
    let problem = "";
    if ([...a].length < 12) problem = "Use at least 12 characters.";
    else if (s.score < 2) problem = "Too easy to guess. Try a few random words.";
    else if (a !== b) problem = b ? "The passphrases do not match." : "Type it again to confirm.";
    hint.textContent = problem;
    next.disabled = Boolean(problem);
  };
  first.addEventListener("input", check);
  second.addEventListener("input", check);
  second.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !next.disabled) next.click();
  });
  next.addEventListener("click", () => {
    wizard.passphrase = first.value;
    go(3);
  });

  body.append(
    ...stepHeader(2, "Share C is your backup. It is encrypted on this Mac with this passphrase (age, scrypt). If you lose this Mac, share C and the judge node can recover the funds."),
    el("label", { class: "field" }, el("span", {}, "Recovery passphrase"), first),
    el("div", { class: "meter-row" }, meter, meterLabel),
    el("label", { class: "field" }, el("span", {}, "Confirm"), second),
    hint,
    el("p", { class: "fine" }, icon("alert", 14), " Nobody can reset it. Write it down and keep it offline."),
    actions(back, next),
  );
  check();
}

// ---- 4. keygen ------------------------------------------------------------------------

function shareTile(letter, title, where, id) {
  return el(
    "div",
    { class: "share-tile", id },
    el("div", { class: "share-letter" }, letter),
    el("div", {}, el("strong", {}, title), el("span", { class: "muted small" }, where)),
  );
}

function keygenStep(body) {
  const list = el(
    "ol",
    { class: "progress-list" },
    KEYGEN_STEPS.map((s) => el("li", { "data-step": s.id }, el("span", { class: "p-dot" }), el("div", {}, el("strong", {}, s.title), s.detail ? el("span", { class: "muted small" }, s.detail) : null))),
  );
  const shares = el(
    "div",
    { class: "share-row" },
    shareTile("A", "Signer share", "This Mac", "tile-a"),
    shareTile("B", "Judge share", "Nitro Enclave", "tile-b"),
    shareTile("C", "Recovery share", "Encrypted on this Mac", "tile-c"),
  );
  const result = el("div", {});
  const next = el("button", { class: "primary hidden" }, el("span", {}, "Continue"), icon("arrowRight", 16));
  next.addEventListener("click", () => go(4));
  const retry = el("button", { class: "ghost hidden" }, "Start over");
  retry.addEventListener("click", () => go(1));

  body.append(
    ...stepHeader(3, "Your Mac and the enclave run the cggmp21 protocol together. The full private key is never assembled anywhere, and any signature needs two of the three shares."),
    shares,
    list,
    result,
    actions(retry, next),
  );

  const order = KEYGEN_STEPS.map((s) => s.id);
  const show = (job) => {
    const at = job.address ? order.length : order.indexOf(job.step);
    list.querySelectorAll("li").forEach((li, i) => {
      li.className = i < at ? "done" : i === at && job.running ? "active" : "";
    });
    const created = at >= 2; // key generation finished
    $("tile-a").classList.toggle("on", created);
    $("tile-c").classList.toggle("on", created);
    $("tile-b").classList.toggle("on", at >= 4);
    shares.classList.toggle("working", job.running);
  };

  const poll = async () => {
    let job;
    try {
      job = await api("/api/setup/progress");
    } catch (e) {
      setTimeout(poll, 1500);
      return;
    }
    show(job);
    if (job.running) {
      setTimeout(poll, 700);
    } else if (job.address) {
      wizard.wallet = job.address;
      wizard.passphrase = "";
      if (wizard.passkey) storeCredential(job.address, wizard.passkey.credential_id);
      remember(4);
      result.replaceChildren(
        el(
          "div",
          { class: "verdict ok" },
          icon("check", 22),
          el("div", {}, el("strong", {}, "Your wallet is ready"), el("div", { class: "addr-big mono" }, job.address), el("p", { class: "muted" }, "Fund it with a little Base Sepolia ETH before the agent sends anything.")),
        ),
      );
      next.classList.remove("hidden");
      next.focus();
    } else if (job.error) {
      result.replaceChildren(el("div", { class: "verdict bad" }, icon("alert", 22), el("div", {}, el("strong", {}, "Key generation failed"), el("p", { class: "mono small" }, job.error))));
      retry.classList.remove("hidden");
    }
  };

  (async () => {
    if (!(wizard.state.job && wizard.state.job.running) && !wizard.wallet) {
      if (!wizard.passkey || !wizard.passphrase) {
        go(1);
        return;
      }
      try {
        await api("/api/setup/keygen", { passphrase: wizard.passphrase, ...wizard.passkey });
      } catch (e) {
        result.replaceChildren(el("div", { class: "verdict bad" }, icon("alert", 22), el("div", {}, el("strong", {}, "Could not start"), el("p", {}, e.message))));
        retry.classList.remove("hidden");
        return;
      }
    }
    wizard.state.job = { running: false };
    poll();
  })();
}

// ---- 5. connect Claude Code -------------------------------------------------------------

function connectStep(body) {
  const code = el("pre", { class: "code" }, "…");
  const copyRow = el("div", { class: "code-actions" });
  const warn = el("div", {});
  const next = el("button", { class: "primary" }, el("span", {}, "Continue"), icon("arrowRight", 16));
  next.addEventListener("click", () => go(5));
  body.append(
    ...stepHeader(4, "Register the signing node A as an MCP server. The agent can then look at the wallet and propose transactions — never sign on its own."),
    el("ol", { class: "numbered" },
      el("li", {}, "Make sure ", el("code", {}, "ALCHEMY_API_KEY"), " is set in your shell."),
      el("li", {}, "Run this in a terminal:"),
    ),
    el("div", { class: "code-wrap" }, code, copyRow),
    warn,
    el("ol", { class: "numbered", start: "3" },
      el("li", {}, "Restart Claude Code and ask: ", el("em", {}, "“Use wallet_info to show my wallet.”")),
    ),
    actions(next),
  );
  api("/api/mcp-command")
    .then(({ command, binary_exists }) => {
      code.textContent = command;
      copyRow.replaceChildren(copyButton(command, "Copy command"));
      if (!binary_exists)
        warn.replaceChildren(el("p", { class: "fine warn-text" }, icon("alert", 14), " mw-node-a is not built yet: run ", el("code", {}, "cargo build --release -p mw-node-a"), " first."));
    })
    .catch((e) => toast(e.message, "error"));
}

// ---- 6. first policy ------------------------------------------------------------------------

function policyStep(body) {
  const text = el("textarea", { rows: "6", spellcheck: "false" }, POLICY_TEMPLATES[0].text);
  const save = el("button", { class: "primary" }, icon("fingerprint", 18), el("span", {}, "Sign & save policy"));
  const skip = el("button", { class: "ghost" }, "Skip for now");
  const finish = () => {
    remember(null);
    wizard.onFinish();
  };
  skip.addEventListener("click", finish);
  save.addEventListener("click", () =>
    busy(save, async () => {
      const r = await signed(wizard.wallet, { kind: "set_policy", text: text.value });
      toast(`Policy v${r.version} saved in the enclave.`);
      finish();
    }),
  );
  body.append(
    ...stepHeader(5, "Write the rules in plain language. The judge compares what each transaction really does — decoded and simulated by the enclave — against this text."),
    el("div", { class: "label" }, "Start from a template"),
    templatePicker((t) => (text.value = t)),
    text,
    el("p", { class: "fine" }, icon("lock", 14), " Only your passkey can change the policy. The agent has no tool for it."),
    actions(skip, save),
  );
}
