// Lockbox UI. Talks only to the local server it was served from. Every value from the
// vault is put into the page with textContent/value, never as HTML.
"use strict";

const $ = (id) => document.getElementById(id);

const ui = {
  state: null,
  entries: [],
  selectedId: null,
  creating: false,
  formDirty: false,
  passwordDirty: false,
  pendingSelect: null,
  deleteArmed: null,
};

// ---- server ------------------------------------------------------------------------------

class ApiError extends Error {
  constructor(message, status, code) { super(message); this.status = status; this.code = code; }
}

async function api(method, path, body) {
  const response = await fetch("/api" + path, {
    method,
    headers: { "X-Lockbox": "1", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 401 || response.status === 403) {
    document.body.textContent = "This tab is no longer signed in to Lockbox. Use the link in the lockbox-ui terminal (press L there for a new one).";
    throw new ApiError("signed out", response.status, "auth");
  }
  const data = response.headers.get("content-type")?.includes("json") ? await response.json() : null;
  if (!response.ok) {
    if (response.status === 423) { await refreshState(); }
    throw new ApiError(data?.error ?? `Request failed (${response.status})`, response.status, data?.code);
  }
  return data;
}

async function busy(button, label, work) {
  const original = button.textContent;
  button.disabled = true;
  if (label) button.textContent = label;
  try { return await work(); }
  finally { button.disabled = false; button.textContent = original; }
}

let toastTimer;
function toast(text) {
  const el = $("toast");
  el.textContent = text;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3500);
}

// ---- state -------------------------------------------------------------------------------

async function refreshState() {
  const state = await api("GET", "/state");
  const firstLoad = ui.state === null;
  const wasUnlocked = ui.state?.unlocked;
  ui.state = state;
  if (!state.unlocked) {
    if (wasUnlocked) {
      // Reload rather than hide: a revealed password, notes and the entry list would otherwise
      // stay in the page, readable with the developer tools by whoever finds the tab.
      stashLockMessage(state.message);
      location.reload();
      return;
    }
    // The status poll comes here every 15 s while locked. Building the lock screen again would
    // empty the password being typed and move the focus, so only a new message is shown.
    if (firstLoad) showLock(state.message ?? takeLockMessage());
    else if (state.message) $("lock-message").textContent = state.message;
    return;
  }
  if (!wasUnlocked) await showMain();
  renderStatus(state);
}

// The lock message survives the reload in sessionStorage (this tab only); without storage it is lost.
function stashLockMessage(message) {
  try { if (message) sessionStorage.setItem("lockMessage", message); } catch { /* no storage */ }
}

function takeLockMessage() {
  try {
    const message = sessionStorage.getItem("lockMessage");
    sessionStorage.removeItem("lockMessage");
    return message;
  } catch { return null; }
}

function renderStatus(state) {
  $("vault-path").textContent = state.path;
  $("vault-path").title = state.path;
  $("dirty-badge").hidden = !state.dirty;
  $("banner-external").hidden = !state.externalChange;
  const conflict = $("banner-conflict");
  conflict.replaceChildren();
  if (state.conflictCopies.length > 0) {
    const text = document.createElement("div");
    text.textContent = "These files beside the vault look like sync-conflict copies. Open each one to check for entries made on another device before deleting it:";
    const list = document.createElement("ul");
    for (const path of state.conflictCopies) {
      const li = document.createElement("li");
      li.textContent = path;
      list.append(li);
    }
    text.append(list);
    conflict.append(text);
  }
  conflict.hidden = state.conflictCopies.length === 0;
  if (state.message) banner(state.message);
}

function banner(text) {
  const el = $("banner-message");
  el.textContent = text;
  el.hidden = !text;
}

// ---- lock screen -------------------------------------------------------------------------

function showLock(message) {
  ui.entries = [];
  ui.selectedId = null;
  $("main-view").hidden = true;
  $("lock-view").hidden = false;
  document.querySelectorAll("dialog[open]").forEach((d) => d.close());
  $("lock-message").textContent = message ?? "";
  $("open-password").value = "";
  if (!$("open-path").value && ui.state?.defaultVaultPath) $("open-path").value = ui.state.defaultVaultPath;
  if (!$("open-keyfile").value && ui.state?.defaultKeyFilePath) $("open-keyfile").value = ui.state.defaultKeyFilePath;
  if ($("open-path").value) inspectPath();
  ($("open-path").value ? $("open-password") : $("open-path")).focus();
}

function selectTab(create) {
  $("tab-open").setAttribute("aria-selected", String(!create));
  $("tab-create").setAttribute("aria-selected", String(create));
  $("open-form").hidden = create;
  $("create-form").hidden = !create;
  $("lock-error").textContent = "";
  if (create && !$("create-suggestion").textContent) suggest();
}

async function inspectPath() {
  const path = $("open-path").value.trim();
  const info = $("open-path-info");
  if (!path) { info.textContent = ""; return; }
  try {
    const result = await api("POST", "/inspect", { path });
    if (!result.exists) {
      info.textContent = "No file at that path.";
      $("open-keyfile-row").hidden = true;
      return;
    }
    info.textContent = result.kdf + (result.requiresKeyFile ? " + key file" : "") + (result.warning ? ". " + result.warning : "");
    $("open-keyfile-row").hidden = !result.requiresKeyFile;
    if (result.requiresKeyFile) await checkKeyFile($("open-keyfile"));
  } catch (e) {
    info.textContent = e.message;
  }
}

async function suggest() {
  const result = await api("POST", "/generate", { length: 0, symbols: false, words: 7 });
  $("create-suggestion").textContent = result.value;
}

function radioValue(name) {
  return document.querySelector(`input[name="${name}"]:checked`).value;
}

// ---- main view ---------------------------------------------------------------------------

async function showMain() {
  $("lock-view").hidden = true;
  $("main-view").hidden = false;
  $("lock-error").textContent = "";
  banner("");
  closeEntry();
  await loadEntries();
  $("search").focus();
}

async function loadEntries() {
  ui.entries = await api("GET", "/entries");
  renderList();
}

function renderList() {
  const filter = $("search").value.trim().toLowerCase();
  const list = $("entry-list");
  list.replaceChildren();
  const shown = ui.entries.filter((e) =>
    !filter || e.title.toLowerCase().includes(filter) || e.username.toLowerCase().includes(filter) || e.url.toLowerCase().includes(filter));
  for (const entry of shown) {
    const li = document.createElement("li");
    li.dataset.id = entry.id;
    li.setAttribute("aria-selected", String(entry.id === ui.selectedId));
    const t = document.createElement("div");
    t.className = "t";
    t.textContent = entry.title;
    const u = document.createElement("div");
    u.className = "u";
    u.textContent = entry.username || entry.url || " ";
    li.append(t, u);
    li.addEventListener("click", () => selectEntry(entry.id));
    list.append(li);
  }
  $("list-empty").hidden = ui.entries.length > 0;
  $("list-empty").textContent = "No entries yet.";
  if (ui.entries.length > 0 && shown.length === 0) {
    $("list-empty").hidden = false;
    $("list-empty").textContent = "Nothing matches.";
  }
}

function guardUnapplied(next) {
  if (!ui.formDirty || ui.pendingSelect === next) {
    ui.pendingSelect = null;
    return true;
  }
  ui.pendingSelect = next;
  toast("This entry has changes you have not applied. Click again to discard them.");
  return false;
}

async function selectEntry(id) {
  if (id === ui.selectedId && !ui.creating) return;
  if (!guardUnapplied(id)) return;
  const entry = await api("GET", `/entries/${id}`);
  fillForm(entry);
}

function newEntry() {
  if (!guardUnapplied("new")) return;
  ui.creating = true;
  ui.selectedId = null;
  fillForm({ title: "", username: "", url: "", notes: "", hasPassword: false, historyCount: 0 });
  renderList();
  generate().then(() => { ui.formDirty = false; });
  $("f-title").focus();
}

function fillForm(entry) {
  ui.creating = !entry.id;
  ui.selectedId = entry.id ?? null;
  ui.formDirty = false;
  ui.passwordDirty = false;
  ui.deleteArmed = null;
  $("detail-empty").hidden = true;
  $("entry-form").hidden = false;
  $("f-title").value = entry.title;
  $("f-username").value = entry.username;
  $("f-url").value = entry.url;
  $("f-notes").value = entry.notes;
  const password = $("f-password");
  password.value = "";
  password.type = "password";
  password.placeholder = entry.hasPassword ? "•••••••• unchanged" : "";
  $("reveal-btn").textContent = "Show";
  $("reveal-btn").disabled = ui.creating;
  $("gen-bits").textContent = "";
  $("history-btn").hidden = !entry.historyCount;
  $("history-btn").textContent = `Password history (${entry.historyCount})`;
  $("history-list").hidden = true;
  $("delete-btn").hidden = ui.creating;
  $("delete-btn").textContent = "Delete";
  $("entry-save").textContent = ui.creating ? "Add entry" : "Apply";
  document.querySelectorAll(".copy").forEach((b) => { b.disabled = ui.creating; });
  $("entry-meta").textContent = entry.modified
    ? `Created ${new Date(entry.created).toLocaleString()} · modified ${new Date(entry.modified).toLocaleString()}`
    : "";
  renderList();
}

function closeEntry() {
  ui.selectedId = null;
  ui.creating = false;
  ui.formDirty = false;
  $("entry-form").hidden = true;
  $("detail-empty").hidden = false;
}

async function applyEntry(event) {
  event.preventDefault();
  const body = {
    title: $("f-title").value,
    username: $("f-username").value,
    password: ui.creating || ui.passwordDirty ? $("f-password").value : null,
    url: $("f-url").value,
    notes: $("f-notes").value,
  };
  const saved = ui.creating
    ? await api("POST", "/entries", body)
    : await api("PUT", `/entries/${ui.selectedId}`, body);
  await loadEntries();
  fillForm(saved);
  await refreshState();
  toast(ui.state.dirty ? "Applied. Save writes it to the vault file." : "Applied.");
}

async function reveal() {
  const field = $("f-password");
  if (field.type === "text") {
    field.type = "password";
    $("reveal-btn").textContent = "Show";
    return;
  }
  if (!ui.passwordDirty) {
    const result = await api("POST", `/entries/${ui.selectedId}/reveal`);
    field.value = result.password;
  }
  field.type = "text";
  $("reveal-btn").textContent = "Hide";
}

async function copy(field) {
  if (ui.creating) return;
  if (ui.formDirty) toast("Copying the stored value - apply your edits first to copy what is on screen.");
  const result = await api("POST", `/entries/${ui.selectedId}/copy`, { field });
  toast(result.message);
}

async function generate() {
  const result = await api("POST", "/generate", {
    length: Number($("gen-length").value) || 32,
    symbols: $("gen-symbols").checked,
    words: 0,
  });
  const field = $("f-password");
  field.value = result.value;
  field.type = "text";
  $("reveal-btn").textContent = "Hide";
  $("reveal-btn").disabled = false;
  $("gen-bits").textContent = `${Math.round(result.bits)} bits`;
  ui.passwordDirty = true;
  ui.formDirty = true;
}

async function showHistory() {
  const list = $("history-list");
  if (!list.hidden) { list.hidden = true; return; }
  const items = await api("POST", `/entries/${ui.selectedId}/history`);
  list.replaceChildren();
  for (const item of items) {
    const li = document.createElement("li");
    const when = document.createElement("span");
    when.className = "when";
    when.textContent = new Date(item.retired).toLocaleString();
    li.append(when, document.createTextNode(item.password));
    list.append(li);
  }
  list.hidden = false;
}

async function deleteEntry() {
  const button = $("delete-btn");
  if (ui.deleteArmed !== ui.selectedId) {
    ui.deleteArmed = ui.selectedId;
    button.textContent = "Click again to delete";
    setTimeout(() => {
      if (ui.deleteArmed) { ui.deleteArmed = null; button.textContent = "Delete"; }
    }, 4000);
    return;
  }
  await api("DELETE", `/entries/${ui.selectedId}`);
  closeEntry();
  await loadEntries();
  await refreshState();
  toast("Deleted. Save writes it to the vault file.");
}

async function save(force) {
  try {
    await busy($("save-btn"), "Saving…", () => api("POST", "/save", { force }));
    await refreshState();
    toast("Saved.");
  } catch (e) {
    if (e.code === "conflict") { $("conflict-dialog").showModal(); return; }
    throw e;
  }
}

function openReload() {
  $("reload-warning").textContent = ui.state?.dirty
    ? "Your unsaved changes here will be lost."
    : "Re-read the vault file from disk.";
  $("reload-password").value = "";
  $("reload-error").textContent = "";
  $("reload-dialog").showModal();
  $("reload-password").focus();
}

async function doReload() {
  try {
    const reloaded = await busy($("reload-submit"), "Unlocking…", () => api("POST", "/reload", { password: $("reload-password").value }));
    $("reload-dialog").close();
    $("reload-password").value = "";
    closeEntry();
    await loadEntries();
    await refreshState();
    if (reloaded.message) banner(reloaded.message);
    toast("Reloaded.");
  } catch (e) {
    $("reload-error").textContent = e.message;
  }
}

function openInfo() {
  const s = ui.state;
  $("i-path").textContent = s.path;
  $("i-kdf").textContent = `AES-256-GCM, key from ${s.kdf}${s.usesKeyFile ? " + key file" : ""}`;
  $("i-count").textContent = `${s.entryCount}${s.dirty ? " (unsaved changes)" : ""}`;
  $("i-backups").textContent = `${s.backupCount} in ${s.backupDirectory}`;
  for (const id of ["p-current", "p-new", "p-confirm", "p-keyfile"]) $(id).value = "";
  $("p-keyfile-hint").hidden = true;
  $("passwd-error").textContent = "";
  $("info-dialog").showModal();
}

async function changePassword() {
  const error = $("passwd-error");
  error.textContent = "";
  if ($("p-new").value !== $("p-confirm").value) { error.textContent = "The new passwords do not match."; return; }
  try {
    const result = await busy($("passwd-submit"), "Re-keying…", () => api("POST", "/passwd", {
      currentPassword: $("p-current").value,
      newPassword: $("p-new").value,
      keyFileMode: radioValue("p-kf"),
      keyFilePath: $("p-keyfile").value || null,
    }));
    $("info-dialog").close();
    banner(result.message);
    await refreshState();
  } catch (e) {
    error.textContent = e.message;
  }
}

// ---- file paths --------------------------------------------------------------------------

// The desktop app's preload (desktop/preload.js) adds this: the real path of a dropped file and
// a native file dialog. A plain browser tab has neither - it never learns where a file lives -
// so there the path is typed or pasted.
const desktop = window.lockboxDesktop ?? null;

/** What the dialog for a field offers: an existing vault, a new one, or a key file (existing or new). */
function pickKind(input) {
  const kind = input.dataset.pick;
  if (kind !== "keyfile") return { kind: "vault", save: kind === "new-vault" };
  const mode = input.id === "create-keyfile" ? radioValue("create-kf") : input.id === "p-keyfile" ? radioValue("p-kf") : "use";
  return { kind: "keyfile", save: mode === "create" };
}

async function browse(input) {
  const { kind, save } = pickKind(input);
  const path = await desktop.pickPath(kind, save);
  input.focus(); // cancelled: the field is still there to type or paste into
  if (path) setPath(input, path);
}

function setPath(input, path) {
  input.value = path;
  input.dispatchEvent(new Event("change", { bubbles: true }));
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

// ---- where key files live ----------------------------------------------------------------

const KEY_FILE_FIELDS = ["open-keyfile", "create-keyfile", "p-keyfile"];

/** "create" when the field names a key file about to be made, else "use". */
function keyFileMode(input) {
  if (input.id === "create-keyfile") return radioValue("create-kf") === "create" ? "create" : "use";
  if (input.id === "p-keyfile") return radioValue("p-kf") === "create" ? "create" : "use";
  return "use";
}

/** Under a key file field: a warning and a way out when it is in Downloads, Desktop, Documents or a cloud folder. */
async function checkKeyFile(input) {
  const hint = $(`${input.id}-hint`);
  const text = hint.querySelector("span");
  const button = hint.querySelector("button");
  const path = input.value.trim();
  if (!path || $(`${input.id}-field`).hidden) { hint.hidden = true; return; }
  const result = await api("POST", "/keyfile/check", { path });
  if (input.value.trim() !== path) return; // changed while we asked
  const note = input.dataset.note;
  delete input.dataset.note;
  if (result.warning && (result.exists || keyFileMode(input) === "create")) {
    text.textContent = result.warning + " ";
    button.textContent = result.exists ? "Move it to Lockbox Keys in your home folder" : "Create it in Lockbox Keys in your home folder instead";
    button.hidden = false;
    hint.hidden = false;
  } else if (note) {
    text.textContent = note;
    button.hidden = true;
    hint.hidden = false;
  } else {
    hint.hidden = true;
  }
}

async function relocateKeyFile(input) {
  const result = await api("POST", "/keyfile/relocate", { path: input.value.trim() });
  input.dataset.note = result.message;
  setPath(input, result.path);
}

function wirePathFields() {
  // A file dropped anywhere else would otherwise be opened in place of the page.
  for (const type of ["dragover", "drop"]) document.addEventListener(type, (e) => e.preventDefault());

  for (const id of KEY_FILE_FIELDS) {
    const input = $(id);
    input.addEventListener("change", () => checkKeyFile(input).catch((err) => toast(err.message)));
    document.querySelector(`button[data-relocate="${id}"]`).addEventListener("click", () =>
      relocateKeyFile(input).catch((err) => toast(err.message)));
  }

  for (const input of document.querySelectorAll("input[data-pick]")) {
    const button = document.querySelector(`button.browse[data-for="${input.id}"]`);
    if (desktop) {
      button.hidden = false;
      button.addEventListener("click", () => browse(input).catch((err) => toast(err.message)));
      // An empty field opens the dialog on click; one with a path in it stays editable.
      input.addEventListener("click", () => { if (!input.value.trim()) browse(input).catch((err) => toast(err.message)); });
    }
    input.addEventListener("dragover", (e) => {
      if (!e.dataTransfer?.types.includes("Files")) return;
      e.dataTransfer.dropEffect = "copy";
      input.classList.add("drop-target");
    });
    input.addEventListener("dragleave", () => input.classList.remove("drop-target"));
    input.addEventListener("drop", (e) => {
      input.classList.remove("drop-target");
      const file = e.dataTransfer?.files[0];
      if (!file) return;
      const path = desktop?.pathForFile(file);
      if (path) setPath(input, path);
      else toast("A browser does not tell the page where a dropped file is. Paste its path, or use the Lockbox desktop app.");
    });
  }
}

// ---- wiring ------------------------------------------------------------------------------

function on(id, event, handler) {
  $(id).addEventListener(event, async (e) => {
    try { await handler(e); }
    catch (err) { if (err.code !== "auth") toast(err.message); }
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  on("tab-open", "click", () => selectTab(false));
  on("tab-create", "click", () => selectTab(true));
  on("open-path", "change", inspectPath);
  on("create-suggest", "click", suggest);
  document.querySelectorAll('input[name="create-kf"]').forEach((r) =>
    r.addEventListener("change", () => {
      $("create-keyfile-field").hidden = radioValue("create-kf") === "none";
      checkKeyFile($("create-keyfile")).catch((err) => toast(err.message));
    }));
  document.querySelectorAll('input[name="p-kf"]').forEach((r) =>
    r.addEventListener("change", () => {
      $("p-keyfile-field").hidden = !["use", "create"].includes(radioValue("p-kf"));
      checkKeyFile($("p-keyfile")).catch((err) => toast(err.message));
    }));

  on("open-form", "submit", async (e) => {
    e.preventDefault();
    $("lock-error").textContent = "";
    try {
      const unlocked = await busy($("open-submit"), "Unlocking…", () => api("POST", "/unlock", {
        path: $("open-path").value,
        password: $("open-password").value,
        keyFilePath: $("open-keyfile-row").hidden ? null : $("open-keyfile").value,
      }));
      $("open-password").value = "";
      await refreshState();
      if (unlocked.message) banner(unlocked.message);
    } catch (err) {
      $("lock-error").textContent = err.message;
      $("open-password").select();
    }
  });

  on("create-form", "submit", async (e) => {
    e.preventDefault();
    $("lock-error").textContent = "";
    if ($("create-password").value !== $("create-confirm").value) {
      $("lock-error").textContent = "The passwords do not match.";
      return;
    }
    const mode = radioValue("create-kf");
    try {
      const result = await busy($("create-submit"), "Creating…", () => api("POST", "/create", {
        path: $("create-path").value,
        password: $("create-password").value,
        keyFilePath: mode === "none" ? null : $("create-keyfile").value,
        createKeyFile: mode === "create",
      }));
      $("create-password").value = "";
      $("create-confirm").value = "";
      await refreshState();
      banner(result.message);
    } catch (err) {
      $("lock-error").textContent = err.message;
    }
  });

  wirePathFields();

  on("search", "input", renderList);
  on("new-btn", "click", newEntry);
  on("entry-form", "submit", applyEntry);
  on("entry-form", "input", (e) => {
    ui.formDirty = true;
    if (e.target.id === "f-password") ui.passwordDirty = true;
  });
  on("reveal-btn", "click", reveal);
  on("gen-btn", "click", generate);
  on("history-btn", "click", showHistory);
  on("delete-btn", "click", deleteEntry);
  document.querySelectorAll(".copy").forEach((b) => b.addEventListener("click", async () => {
    try { await copy(b.dataset.field); } catch (err) { toast(err.message); }
  }));

  on("save-btn", "click", () => save(false));
  on("lock-btn", "click", async () => {
    if (ui.state?.dirty && $("lock-btn").dataset.armed !== "1") {
      $("lock-btn").dataset.armed = "1";
      $("lock-btn").textContent = "Lock without saving?";
      setTimeout(() => { $("lock-btn").dataset.armed = ""; $("lock-btn").textContent = "Lock"; }, 4000);
      return;
    }
    $("lock-btn").dataset.armed = "";
    $("lock-btn").textContent = "Lock";
    await api("POST", "/lock");
    await refreshState();
  });
  on("quit-btn", "click", async () => {
    if (ui.state?.dirty && $("quit-btn").dataset.armed !== "1") {
      $("quit-btn").dataset.armed = "1";
      $("quit-btn").textContent = "Quit without saving?";
      setTimeout(() => { $("quit-btn").dataset.armed = ""; $("quit-btn").textContent = "Quit"; }, 4000);
      return;
    }
    const result = await api("POST", "/quit");
    document.body.textContent = result.message;
  });
  on("info-btn", "click", openInfo);
  on("passwd-submit", "click", changePassword);
  on("banner-reload", "click", openReload);
  on("reload-submit", "click", doReload);
  on("reload-password", "keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); return doReload(); } });
  on("conflict-reload", "click", () => { $("conflict-dialog").close(); openReload(); });
  on("conflict-force", "click", async () => { $("conflict-dialog").close(); await save(true); });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s" && ui.state?.unlocked) {
      e.preventDefault();
      save(false).catch((err) => toast(err.message));
    }
  });
  window.addEventListener("beforeunload", (e) => {
    if (ui.state?.unlocked && (ui.state.dirty || ui.formDirty)) e.preventDefault();
  });

  // Status (external changes, idle lock) without counting as activity on the server.
  setInterval(() => { refreshState().catch(() => {}); }, 15000);

  try { await refreshState(); } catch { /* signed out: body already replaced */ }
});
