#!/usr/bin/env node
// Runtime proof that the vault actually encrypts/decrypts — the static audit only
// checks that the code is shaped right. Extracts the vault module out of panel.js
// and exercises create -> seal -> lock -> unlock -> reveal against Node's WebCrypto.
"use strict";
const fs = require("fs"), path = require("path"), vm = require("vm");

const src = fs.readFileSync(path.join(__dirname, "..", "panel.js"), "utf8");
const start = src.indexOf("// ═══════════════════════════ SECRET VAULT");
const end = src.indexOf("// ── Vault UI ─");
if (start < 0 || end < 0) { console.error("could not slice vault module"); process.exit(1); }
const vaultSrc = src.slice(start, end);

// Fail loudly rather than silently testing a truncated or empty slice — otherwise
// moving the module's markers would turn this whole suite into a no-op that passes.
const REQUIRED = ["vaultDeriveKey", "vaultEncrypt", "vaultDecrypt", "vaultCreate", "vaultUnlock",
  "vaultLock", "vaultRevealSecrets", "vaultSealSettings", "vaultSealProjects", "vaultRedact"];
const missing = REQUIRED.filter(fn => !vaultSrc.includes("function " + fn));
if (missing.length) { console.error("vault slice is missing: " + missing.join(", ")); process.exit(1); }

// Top-level let/const in a vm script live in the context's lexical scope, not on
// the sandbox object, so expose the internals the assertions need to inspect.
const EPILOGUE = `
globalThis.__v = {
  get meta() { return vaultMeta; },
  get key() { return vaultKey; },
  get undecryptable() { return vaultUndecryptable; },
  get legacySettings() { return vaultLegacySettingKeys; },
  get legacyProjects() { return vaultLegacyProjectKeys; },
  // loadSettings/pentestLoadProjects live outside the slice, so stand in for them.
  markLoaded() { vaultMarkSettingsLoaded(); vaultMarkProjectsLoaded(); },
};`;

// Minimal panel-ish environment
const store = {};
const sandbox = {
  crypto: require("crypto").webcrypto,
  TextEncoder, TextDecoder,
  btoa: s => Buffer.from(s, "binary").toString("base64"),
  atob: s => Buffer.from(s, "base64").toString("binary"),
  console,
  chrome: {
    storage: {
      local: {
        get: (keys, cb) => {
          const k = Array.isArray(keys) ? keys : [keys];
          cb(Object.fromEntries(k.filter(x => x in store).map(x => [x, store[x]])));
        },
        set: (obj, cb) => { Object.assign(store, JSON.parse(JSON.stringify(obj))); cb && cb(); },
      },
    },
  },
  settings: {},
  pentestProjects: [],
};
vm.createContext(sandbox);
vm.runInContext(vaultSrc + EPILOGUE, sandbox);
sandbox.__v.markLoaded();

let pass = 0, fail = 0;
const t = (name, ok) => { ok ? pass++ : (fail++, console.log("  FAIL: " + name)); };

(async () => {
  const S = sandbox;

  // ── 1. Fresh state: no vault, secrets are not persisted ──
  t("starts locked", !S.vaultUnlocked());
  t("no vault yet", !S.vaultExists());
  S.settings.aiPrimaryKey = "sk-super-secret-123";
  S.settings.authPass = "hunter2";
  let sealed = await S.vaultSealSettings(S.settings);
  t("locked: plaintext key not persisted", sealed.aiPrimaryKey === "");
  t("locked: plaintext authPass not persisted", sealed.authPass === "");
  t("locked: no ciphertext invented", Object.keys(sealed.__secrets).length === 0);
  t("locked: unsaved-secret warning fires", S.vaultHasUnsavedSecrets());

  // ── 2. Create the vault, then seal ──
  await S.vaultCreate("correct horse battery staple");
  t("vault exists after create", S.vaultExists());
  t("unlocked after create", S.vaultUnlocked());

  S.pentestProjects.push({ id: "p1", credentials: { username: "admin", password: "pw123", apiToken: "tok-abc" } });
  sealed = await S.vaultSealSettings(S.settings);
  const sealedProjects = await S.vaultSealProjects(S.pentestProjects);

  t("sealed: aiPrimaryKey blanked", sealed.aiPrimaryKey === "");
  t("sealed: ciphertext present", !!sealed.__secrets.aiPrimaryKey?.ct && !!sealed.__secrets.aiPrimaryKey?.iv);
  t("sealed: authPass encrypted", !!sealed.__secrets.authPass?.ct);
  const blobJson = JSON.stringify(sealed);
  t("sealed: plaintext absent from serialized settings",
    !blobJson.includes("sk-super-secret-123") && !blobJson.includes("hunter2"));
  const projJson = JSON.stringify(sealedProjects);
  t("sealed: project password blanked", sealedProjects[0].credentials.password === "");
  t("sealed: project plaintext absent", !projJson.includes("pw123") && !projJson.includes("tok-abc"));
  t("sealed: non-secret project field kept", sealedProjects[0].credentials.username === "admin");
  t("no unsaved-secret warning while unlocked", !S.vaultHasUnsavedSecrets());

  // Each encryption uses a fresh IV
  const a = await S.vaultEncrypt("same"), b = await S.vaultEncrypt("same");
  t("IV is random per encryption", a.iv !== b.iv && a.ct !== b.ct);

  // ── 3. Lock wipes memory ──
  S.settings.__secrets = sealed.__secrets;
  S.pentestProjects[0].credentials.__secrets = sealedProjects[0].credentials.__secrets;
  S.vaultLock();
  t("locked: key gone", !S.vaultUnlocked());
  t("locked: settings plaintext wiped", S.settings.aiPrimaryKey === "");
  t("locked: project plaintext wiped", S.pentestProjects[0].credentials.password === "");
  t("locked: ciphertext retained", !!S.settings.__secrets.aiPrimaryKey);

  // Sealing while locked must carry ciphertext forward, not destroy it
  const resealed = await S.vaultSealSettings(S.settings);
  t("locked reseal preserves ciphertext",
    resealed.__secrets.aiPrimaryKey?.ct === sealed.__secrets.aiPrimaryKey.ct);

  // ── 4. Wrong passphrase is rejected ──
  t("wrong passphrase rejected", (await S.vaultUnlock("not the passphrase")) === false);
  t("still locked after bad attempt", !S.vaultUnlocked());
  t("bad attempt did not leak plaintext", S.settings.aiPrimaryKey === "");

  // ── 5. Correct passphrase restores everything ──
  t("correct passphrase accepted", (await S.vaultUnlock("correct horse battery staple")) === true);
  t("aiPrimaryKey restored", S.settings.aiPrimaryKey === "sk-super-secret-123");
  t("authPass restored", S.settings.authPass === "hunter2");
  t("project password restored", S.pentestProjects[0].credentials.password === "pw123");
  t("project apiToken restored", S.pentestProjects[0].credentials.apiToken === "tok-abc");

  // ── 6. Tampered ciphertext fails the GCM auth tag ──
  const good = S.settings.__secrets.aiPrimaryKey;
  const tampered = { iv: good.iv, ct: S.btoa(S.atob(good.ct).replace(/./, c => String.fromCharCode(c.charCodeAt(0) ^ 1))) };
  let threw = false;
  try { await S.vaultDecrypt(tampered); } catch { threw = true; }
  t("tampered ciphertext rejected", threw);

  // ── 7. Re-key: change passphrase, old one stops working ──
  // vaultCreate re-encrypts settings AND projects and commits them with the new
  // metadata in one write, so no separate reseal is needed here. Dropping the
  // project half of that used to pass every test while silently destroying every
  // stored credential — hence the explicit project assertions below.
  const oldSalt = S.__v.meta.salt;
  await S.vaultCreate("a brand new passphrase");
  t("re-key rotated the salt", S.__v.meta.salt !== oldSalt);
  t("re-key produced fresh ciphertext", S.settings.__secrets.aiPrimaryKey.ct !== good.ct);
  t("re-key persisted settings ciphertext", !!store.voidSettings.__secrets.aiPrimaryKey.ct);
  t("re-key persisted project ciphertext", !!store.voidPentestProjects[0].credentials.__secrets.password.ct);

  S.vaultLock();
  t("old passphrase no longer works", (await S.vaultUnlock("correct horse battery staple")) === false);
  t("new passphrase works", (await S.vaultUnlock("a brand new passphrase")) === true);
  t("settings secrets survive re-key", S.settings.aiPrimaryKey === "sk-super-secret-123");
  t("authPass survives re-key", S.settings.authPass === "hunter2");
  t("project password survives re-key", S.pentestProjects[0].credentials.password === "pw123");
  t("project apiToken survives re-key", S.pentestProjects[0].credentials.apiToken === "tok-abc");

  // ── 7b. An unreadable blob is preserved, never overwritten with "" ──
  // `good` is aiPrimaryKey's ciphertext from BEFORE the re-key, so planting it
  // under the new key is exactly the corruption an interrupted re-key would leave.
  const realAuthBlob = S.settings.__secrets.authPass;
  S.settings.__secrets.authPass = { iv: good.iv, ct: good.ct };
  S.vaultLock();
  await S.vaultUnlock("a brand new passphrase");
  t("undecryptable blob is recorded", S.__v.undecryptable.has("authPass"));
  t("undecryptable field reads empty", S.settings.authPass === "");
  const afterFail = await S.vaultSealSettings(S.settings);
  t("undecryptable ciphertext is preserved, not dropped", afterFail.__secrets.authPass?.ct === good.ct);
  t("other secrets still sealed normally", !!afterFail.__secrets.aiPrimaryKey?.ct);
  // restore for the sections below
  S.__v.undecryptable.clear();
  S.settings.__secrets.authPass = realAuthBlob;
  S.settings.authPass = "hunter2";

  // ── 8. Redaction for exports ──
  const red = S.vaultRedact(S.settings);
  const redJson = JSON.stringify(red);
  t("redact drops plaintext", red.aiPrimaryKey === undefined && red.authPass === undefined);
  t("redact drops ciphertext", red.__secrets === undefined);
  t("redact leaves nothing sensitive",
    !redJson.includes("sk-super-secret-123") && !redJson.includes("hunter2"));

  // ── 9. Nothing sensitive ever reached the fake chrome.storage ──
  // vaultCreate writes voidSettings and voidPentestProjects itself, so this sweep
  // covers real persisted payloads rather than just the salt+verifier blob.
  const diskJson = JSON.stringify(store);
  t("settings were actually persisted", !!store.voidSettings);
  t("projects were actually persisted", Array.isArray(store.voidPentestProjects));
  t("vault metadata stored", !!store.voidVault?.salt && !!store.voidVault?.verifier);
  t("no derived key on disk", !("key" in (store.voidVault || {})));
  t("persisted settings hold no plaintext secret",
    store.voidSettings.aiPrimaryKey === "" && store.voidSettings.authPass === "");
  t("persisted project holds no plaintext credential",
    store.voidPentestProjects[0].credentials.password === "" &&
    store.voidPentestProjects[0].credentials.apiToken === "");
  t("no plaintext ever written to storage",
    !diskJson.includes("sk-super-secret-123") && !diskJson.includes("hunter2") &&
    !diskJson.includes("pw123") && !diskJson.includes("tok-abc") &&
    !diskJson.includes("battery staple") && !diskJson.includes("brand new passphrase"));

  // ── 10. Legacy plaintext is not destroyed by an unrelated save ──
  // Fresh sandbox: simulate an upgrade from a build that stored keys in the clear.
  const store2 = {};
  const sb2 = vm.createContext({
    crypto: require("crypto").webcrypto, TextEncoder, TextDecoder,
    btoa: sandbox.btoa, atob: sandbox.atob, console,
    chrome: { storage: { local: {
      get: (keys, cb) => { const k = Array.isArray(keys) ? keys : [keys];
        cb(Object.fromEntries(k.filter(x => x in store2).map(x => [x, store2[x]]))); },
      set: (obj, cb) => { Object.assign(store2, JSON.parse(JSON.stringify(obj))); cb && cb(); },
    } } },
    settings: { aiPrimaryKey: "legacy-plaintext-key" },
    pentestProjects: [],
  });
  vm.runInContext(vaultSrc + EPILOGUE, sb2);
  sb2.__v.markLoaded();
  sb2.__v.legacySettings.add("aiPrimaryKey"); // what loadSettings does on upgrade

  const legacySealed = await sb2.vaultSealSettings(sb2.settings);
  t("legacy plaintext survives an unrelated save", legacySealed.aiPrimaryKey === "legacy-plaintext-key");
  t("legacy save is not counted as a dropped secret", sb2.vaultDroppedSecretKeys().length === 0);

  // A brand-new secret typed with no vault is still never written.
  sb2.settings.aiJudgeKey = "brand-new-typed-key";
  const mixed = await sb2.vaultSealSettings(sb2.settings);
  t("newly typed secret is still not persisted", mixed.aiJudgeKey === "");
  t("newly typed secret is reported as dropped", sb2.vaultDroppedSecretKeys().includes("aiJudgeKey"));

  // Once a passphrase is set, the legacy plaintext is encrypted and leaves disk.
  await sb2.vaultCreate("a legacy migration passphrase");
  t("migration encrypted the legacy key", !!store2.voidSettings.__secrets.aiPrimaryKey?.ct);
  t("migration removed the plaintext", store2.voidSettings.aiPrimaryKey === "");
  t("migration cleared the legacy marker", sb2.__v.legacySettings.size === 0);
  t("no legacy plaintext left on disk", !JSON.stringify(store2).includes("legacy-plaintext-key"));

  console.log("\n" + "=".repeat(60));
  console.log("VAULT RUNTIME: " + pass + " PASS, " + fail + " FAIL");
  console.log("=".repeat(60));
  process.exit(fail > 0 ? 1 : 0);
})();
