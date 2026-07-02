import { useCallback, useEffect, useMemo, useState } from "react";
import type { EncryptedCipher, SyncResponse, CipherData } from "@omnisecure/core";
import { analyzeVaultHealth, generatePassword, parseBitwardenCsv, bitwardenRowsToCipherData, parseBitwardenJson, enrichVaultHealthWithBreaches, checkPasswordPwned, generateTotp, exportBitwardenCsv, exportBitwardenJson } from "@omnisecure/core";
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/browser";
import {
  decryptBytesBrowser,
  decryptJsonBrowser,
  encryptBytesBrowser,
  encryptJsonBrowser,
  randomKeyBrowser,
  unlockSymmetricKeyBrowser,
} from "@omnisecure/crypto/browser";
import { api, clearSession, loadSession, saveSession, type Session } from "./api";
import { encodeSendKey, sendKeyFromPassword } from "./send-utils";

type View = "vault" | "send" | "secrets" | "tools" | "health" | "import" | "export" | "emergency" | "orgs" | "security";

function completeSession(
  data: { token: string; user: { email: string }; userKeys: Session["userKeys"] },
): Session {
  return { token: data.token, email: data.user.email, userKeys: data.userKeys };
}

export function App() {
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [view, setView] = useState<View>("vault");
  const [sync, setSync] = useState<SyncResponse | null>(null);
  const [unlocked, setUnlocked] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [symmetricKey, setSymmetricKey] = useState<Uint8Array | null>(null);
  const [ssoNotice, setSsoNotice] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    if (!token) return;
    void (async () => {
      try {
        const data = await api<{
          user: { email: string };
          userKeys: Session["userKeys"];
        }>("/api/auth/me", {}, token);
        const next = completeSession({ token, user: data.user, userKeys: data.userKeys });
        saveSession(next);
        setSession(next);
        setSsoNotice(params.get("sso") === "saml"
          ? "Signed in with SAML SSO. Unlock with your master password to decrypt the vault."
          : "Signed in with SSO. Unlock with your master password to decrypt the vault.");
        window.history.replaceState({}, "", window.location.pathname);
      } catch (e) {
        setError(e instanceof Error ? e.message : "SSO sign-in failed");
      }
    })();
  }, []);

  const decryptedCiphers = useMemo(() => {
    if (!sync || !symmetricKey) return [];
    return sync.ciphers.map((cipher) => {
      try {
        // Sync decrypt happens async in real app; placeholder empty until loaded
        return { ...cipher, data: {} as CipherData };
      } catch {
        return { ...cipher, data: {} as CipherData };
      }
    });
  }, [sync, symmetricKey]);

  const [decrypted, setDecrypted] = useState<Array<EncryptedCipher & { data: CipherData }>>([]);

  useEffect(() => {
    if (!sync || !symmetricKey) {
      setDecrypted([]);
      return;
    }
    void (async () => {
      const items = await Promise.all(
        sync.ciphers.map(async (cipher) => {
          try {
            const data = await decryptJsonBrowser<CipherData>(symmetricKey, cipher.encryptedData);
            return { ...cipher, data };
          } catch {
            return { ...cipher, data: {} as CipherData };
          }
        }),
      );
      setDecrypted(items);
    })();
  }, [sync, symmetricKey]);

  const refreshSync = useCallback(async (token: string) => {
    const data = await api<SyncResponse>("/api/vault/sync", {}, token);
    setSync(data);
  }, []);

  useEffect(() => {
    if (session?.token && unlocked && symmetricKey) {
      refreshSync(session.token).catch((e: Error) => setError(e.message));
    }
  }, [session, unlocked, symmetricKey, refreshSync]);

  async function handleAuth(mode: "login" | "register", email: string, password: string, name?: string) {
    setLoading(true);
    setError("");
    try {
      const path = mode === "login" ? "/api/auth/login" : "/api/auth/register";
      const body = mode === "login"
        ? { email, masterPassword: password }
        : { email, masterPassword: password, name };
      const data = await api<{
        token: string;
        user: { email: string };
        userKeys: Session["userKeys"];
      }>(path, { method: "POST", body: JSON.stringify(body) });
      const next = completeSession(data);
      saveSession(next);
      setSession(next);
      const key = await unlockSymmetricKeyBrowser(password, email, data.userKeys);
      setSymmetricKey(key);
      setUnlocked(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  }

  function handleLogout() {
    clearSession();
    setSession(null);
    setSync(null);
    setUnlocked(false);
    setSymmetricKey(null);
  }

  if (!session) {
    return <AuthScreen onAuth={handleAuth} onPasskeySession={(next) => { saveSession(next); setSession(next); }} loading={loading} error={error} />;
  }

  if (!unlocked) {
    return (
      <UnlockScreen
        email={session.email}
        notice={ssoNotice}
        onUnlock={async (password) => {
          try {
            const key = await unlockSymmetricKeyBrowser(password, session.email, session.userKeys);
            setSymmetricKey(key);
            setUnlocked(true);
            setError("");
          } catch {
            setError("Invalid master password");
          }
        }}
        onLogout={handleLogout}
        error={error}
      />
    );
  }

  const health = analyzeVaultHealth(decrypted.length ? decrypted : decryptedCiphers);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">OS</div>
          <div>
            <strong>OmniSecure</strong>
            <span>OmniTender identity suite</span>
          </div>
        </div>
        <nav>
          <button className={view === "vault" ? "active" : ""} onClick={() => setView("vault")}>Vault</button>
          <button className={view === "send" ? "active" : ""} onClick={() => setView("send")}>Send</button>
          <button className={view === "secrets" ? "active" : ""} onClick={() => setView("secrets")}>Secrets</button>
          <button className={view === "tools" ? "active" : ""} onClick={() => setView("tools")}>Tools</button>
          <button className={view === "health" ? "active" : ""} onClick={() => setView("health")}>Health</button>
          <button className={view === "import" ? "active" : ""} onClick={() => setView("import")}>Import</button>
          <button className={view === "export" ? "active" : ""} onClick={() => setView("export")}>Export</button>
          <button className={view === "orgs" ? "active" : ""} onClick={() => setView("orgs")}>Organizations</button>
          <button className={view === "security" ? "active" : ""} onClick={() => setView("security")}>Security</button>
          <button className={view === "emergency" ? "active" : ""} onClick={() => setView("emergency")}>Emergency</button>
        </nav>
        <div className="sidebar-footer">
          <span>{session.email}</span>
          <button className="ghost" onClick={handleLogout}>Lock & sign out</button>
        </div>
      </aside>

      <main>
        {view === "vault" && symmetricKey && (
          <VaultView
            ciphers={decrypted}
            folders={sync?.folders ?? []}
            token={session.token}
            symmetricKey={symmetricKey}
            onRefresh={() => refreshSync(session.token)}
          />
        )}
        {view === "send" && <SendView token={session.token} />}
        {view === "secrets" && <SecretsView token={session.token} organizations={sync?.organizations ?? []} />}
        {view === "tools" && <ToolsView />}
        {view === "health" && <HealthView report={health} ciphers={decrypted.length ? decrypted : decryptedCiphers} />}
        {view === "import" && symmetricKey && (
          <ImportView token={session.token} symmetricKey={symmetricKey} onRefresh={() => refreshSync(session.token)} />
        )}
        {view === "export" && (
          <ExportView ciphers={decrypted} folders={sync?.folders ?? []} />
        )}
        {view === "orgs" && (
          <OrgsView token={session.token} organizations={sync?.organizations ?? []} onRefresh={() => refreshSync(session.token)} />
        )}
        {view === "emergency" && symmetricKey && (
          <EmergencyView token={session.token} email={session.email} symmetricKey={symmetricKey} />
        )}
        {view === "security" && (
          <SecurityView token={session.token} email={session.email} />
        )}
      </main>
    </div>
  );
}

function AuthScreen({
  onAuth,
  onPasskeySession,
  loading,
  error,
}: {
  onAuth: (mode: "login" | "register", email: string, password: string, name?: string) => void;
  onPasskeySession: (session: Session) => void;
  loading: boolean;
  error: string;
}) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [passkeyError, setPasskeyError] = useState("");
  const [passkeyBusy, setPasskeyBusy] = useState(false);

  async function signInWithPasskey() {
    setPasskeyBusy(true);
    setPasskeyError("");
    try {
      const { startAuthentication } = await import("@simplewebauthn/browser");
      const options = await api<import("@simplewebauthn/browser").PublicKeyCredentialRequestOptionsJSON>(
        "/api/webauthn/login/options",
        { method: "POST", body: JSON.stringify({ email: email || undefined }) },
      );
      const response = await startAuthentication({ optionsJSON: options });
      const data = await api<{
        token: string;
        user: { email: string };
        userKeys: Session["userKeys"];
      }>("/api/webauthn/login/verify", {
        method: "POST",
        body: JSON.stringify({ response }),
      });
      onPasskeySession(completeSession(data));
    } catch (e) {
      setPasskeyError(e instanceof Error ? e.message : "Passkey sign-in failed");
    } finally {
      setPasskeyBusy(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="brand large">
          <div className="brand-mark">OS</div>
          <div>
            <h1>OmniSecure</h1>
            <p>Zero-knowledge password manager for the OmniTender ecosystem</p>
          </div>
        </div>
        <div className="tabs">
          <button className={mode === "login" ? "active" : ""} onClick={() => setMode("login")}>Sign in</button>
          <button className={mode === "register" ? "active" : ""} onClick={() => setMode("register")}>Create account</button>
        </div>
        <form onSubmit={(e) => { e.preventDefault(); onAuth(mode, email, password, name); }}>
          {mode === "register" && (
            <label>
              Name
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name" />
            </label>
          )}
          <label>
            Email
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@omnitender.us" />
          </label>
          <label>
            Master password
            <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Never shared with the server" />
          </label>
          {(error || passkeyError) && <p className="error">{error || passkeyError}</p>}
          <button type="submit" disabled={loading}>{loading ? "Working…" : mode === "login" ? "Unlock vault" : "Create vault"}</button>
        </form>
        {mode === "login" && (
          <button type="button" className="ghost" disabled={passkeyBusy} onClick={() => void signInWithPasskey()}>
            {passkeyBusy ? "Waiting for passkey…" : "Sign in with passkey"}
          </button>
        )}
        <p className="hint">End-to-end encrypted. OmniSecure servers store ciphertext only — your master password never leaves this device.</p>
      </div>
    </div>
  );
}

function UnlockScreen({
  email,
  notice,
  onUnlock,
  onLogout,
  error,
}: {
  email: string;
  notice?: string;
  onUnlock: (password: string) => void | Promise<void>;
  onLogout: () => void;
  error: string;
}) {
  const [password, setPassword] = useState("");
  return (
    <div className="auth-page">
      <div className="auth-card">
        <h2>Unlock vault</h2>
        <p>Signed in as <strong>{email}</strong></p>
        {notice && <p className="hint">{notice}</p>}
        <form onSubmit={(e) => { e.preventDefault(); void onUnlock(password); }}>
          <label>
            Master password
            <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          </label>
          {error && <p className="error">{error}</p>}
          <button type="submit">Unlock</button>
        </form>
        <button className="ghost" onClick={onLogout}>Use a different account</button>
      </div>
    </div>
  );
}

function VaultView({
  ciphers,
  folders,
  token,
  symmetricKey,
  onRefresh,
}: {
  ciphers: Array<EncryptedCipher & { data: CipherData }>;
  folders: SyncResponse["folders"];
  token: string;
  symmetricKey: Uint8Array;
  onRefresh: () => void;
}) {
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  async function addLogin() {
    const encryptedData = await encryptJsonBrowser(symmetricKey, { username, password, uris: [] });
    await api("/api/vault/ciphers", {
      method: "POST",
      body: JSON.stringify({ type: "login", name, encryptedData }),
    }, token);
    setName("");
    setUsername("");
    setPassword("");
    onRefresh();
  }

  return (
    <section className="panel">
      <header>
        <div>
          <h2>My vault</h2>
          <p>{ciphers.length} items · {folders.length} folders</p>
        </div>
      </header>

      <div className="grid two">
        <div className="card">
          <h3>Add login</h3>
          <label>Name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="GitHub" /></label>
          <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} /></label>
          <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          <button onClick={() => void addLogin()} disabled={!name}>Save encrypted item</button>
        </div>

        <div className="card list">
          <h3>Items</h3>
          {ciphers.length === 0 ? <p className="muted">No items yet.</p> : (
            <ul>
              {ciphers.map((c) => (
                <li key={c.id}>
                  <strong>{c.name}</strong>
                  <span className="tag">{c.type}</span>
                  {"username" in c.data && Boolean(c.data.username) && (
                    <code>{String((c.data as { username?: string }).username)}</code>
                  )}
                  {"totp" in c.data && Boolean((c.data as { totp?: string }).totp) && (
                    <TotpBadge secret={String((c.data as { totp?: string }).totp)} />
                  )}
                  <CipherAttachments cipherId={c.id} token={token} symmetricKey={symmetricKey} />
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}

interface VaultAttachment {
  id: string;
  cipherId: string;
  fileName: string;
  size: number;
  encryptedData: { iv: string; data: string };
}

function CipherAttachments({
  cipherId,
  token,
  symmetricKey,
}: {
  cipherId: string;
  token: string;
  symmetricKey: Uint8Array;
}) {
  const [attachments, setAttachments] = useState<VaultAttachment[]>([]);
  const [status, setStatus] = useState("");

  async function refresh() {
    const data = await api<{ attachments: VaultAttachment[] }>(
      `/api/vault/ciphers/${cipherId}/attachments`,
      {},
      token,
    );
    setAttachments(data.attachments);
  }

  useEffect(() => {
    void refresh().catch(() => setAttachments([]));
  }, [cipherId, token]);

  async function uploadFile(file: File) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const encryptedData = await encryptBytesBrowser(symmetricKey, bytes);
    await api(`/api/vault/ciphers/${cipherId}/attachments`, {
      method: "POST",
      body: JSON.stringify({ fileName: file.name, size: file.size, encryptedData }),
    }, token);
    setStatus(`Uploaded ${file.name}`);
    await refresh();
  }

  async function downloadAttachment(attachment: VaultAttachment) {
    const bytes = await decryptBytesBrowser(symmetricKey, attachment.encryptedData);
    const copy = bytes.slice();
    const blob = new Blob([copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength)]);
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = attachment.fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function deleteAttachment(attachmentId: string) {
    await api(`/api/vault/ciphers/${cipherId}/attachments/${attachmentId}`, { method: "DELETE" }, token);
    await refresh();
  }

  return (
    <div className="attachments">
      <label className="file-upload">
        Attach file
        <input
          type="file"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void uploadFile(file).catch((err: Error) => setStatus(err.message));
            e.target.value = "";
          }}
        />
      </label>
      {attachments.length > 0 && (
        <ul>
          {attachments.map((attachment) => (
            <li key={attachment.id}>
              {attachment.fileName} ({Math.round(attachment.size / 1024)} KB)
              <button type="button" className="ghost" onClick={() => void downloadAttachment(attachment)}>Download</button>
              <button type="button" className="ghost" onClick={() => void deleteAttachment(attachment.id)}>Delete</button>
            </li>
          ))}
        </ul>
      )}
      {status && <p className="hint">{status}</p>}
    </div>
  );
}

function SendView({ token }: { token: string }) {
  const [text, setText] = useState("");
  const [sendPassword, setSendPassword] = useState("");
  const [link, setLink] = useState("");

  async function createSend() {
    const accessId = crypto.randomUUID().replace(/-/g, "").slice(0, 18);
    const sendKey = sendPassword
      ? await sendKeyFromPassword(sendPassword, accessId)
      : randomKeyBrowser();
    const encryptedPayload = await encryptJsonBrowser(sendKey, text);
    const data = await api<{ accessId: string }>("/api/send", {
      method: "POST",
      body: JSON.stringify({
        type: "text",
        name: "Shared note",
        accessId,
        password: sendPassword || undefined,
        encryptedPayload,
      }),
    }, token);
    const keyFragment = sendPassword ? "" : `#k=${encodeSendKey(sendKey)}`;
    setLink(`${window.location.origin}/send/${data.accessId}${keyFragment}`);
  }

  return (
    <section className="panel">
      <header><h2>OmniSecure Send</h2><p>Share encrypted text with expiring links — like Bitwarden Send.</p></header>
      <div className="card">
        <label>Message<textarea value={text} onChange={(e) => setText(e.target.value)} rows={5} /></label>
        <label>Optional Send password<input type="password" value={sendPassword} onChange={(e) => setSendPassword(e.target.value)} /></label>
        <button onClick={() => void createSend()} disabled={!text}>Create secure link</button>
        {link && <p className="success">Link created: <code>{link}</code></p>}
      </div>
    </section>
  );
}

function SecretsView({ token, organizations }: { token: string; organizations: SyncResponse["organizations"] }) {
  const [orgId, setOrgId] = useState(organizations[0]?.id ?? "");
  const [projects, setProjects] = useState<Array<{ id: string; name: string }>>([]);
  const [newProject, setNewProject] = useState("");

  async function loadProjects(id: string) {
    if (!id) return;
    const data = await api<{ projects: Array<{ id: string; name: string }> }>(`/api/secrets/organizations/${id}/projects`, {}, token);
    setProjects(data.projects);
  }

  async function createProject() {
    await api(`/api/secrets/organizations/${orgId}/projects`, {
      method: "POST",
      body: JSON.stringify({ name: newProject }),
    }, token);
    setNewProject("");
    loadProjects(orgId);
  }

  useEffect(() => {
    if (orgId) void loadProjects(orgId);
  }, [orgId]);

  return (
    <section className="panel">
      <header><h2>Secrets Manager</h2><p>Infrastructure secrets for dev teams — API keys, DB passwords, certificates.</p></header>
      {!organizations.length ? (
        <div className="card"><p className="muted">Create an organization first to use Secrets Manager.</p></div>
      ) : (
        <div className="card">
          <label>Organization
            <select value={orgId} onChange={(e) => setOrgId(e.target.value)}>
              {organizations.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          </label>
          <label>New project<input value={newProject} onChange={(e) => setNewProject(e.target.value)} /></label>
          <button onClick={() => void createProject()} disabled={!newProject}>Create project</button>
          <ul>{projects.map((p) => <li key={p.id}>{p.name}</li>)}</ul>
        </div>
      )}
    </section>
  );
}

function ToolsView() {
  const [password, setPassword] = useState(() => generatePassword());
  return (
    <section className="panel">
      <header><h2>Security tools</h2><p>Free generators — password, passphrase, username.</p></header>
      <div className="card">
        <code className="mono">{password}</code>
        <button onClick={() => setPassword(generatePassword())}>Regenerate password</button>
      </div>
    </section>
  );
}

function HealthView({
  report,
  ciphers,
}: {
  report: ReturnType<typeof analyzeVaultHealth>;
  ciphers: Array<EncryptedCipher & { data: CipherData }>;
}) {
  const [breachReport, setBreachReport] = useState(report);
  const [checking, setChecking] = useState(false);
  const [breachError, setBreachError] = useState("");

  useEffect(() => {
    setBreachReport(report);
  }, [report]);

  async function runBreachCheck() {
    setChecking(true);
    setBreachError("");
    try {
      const enriched = await enrichVaultHealthWithBreaches(report, ciphers, checkPasswordPwned);
      setBreachReport(enriched);
    } catch (e) {
      setBreachError(e instanceof Error ? e.message : "Breach check failed");
    } finally {
      setChecking(false);
    }
  }

  return (
    <section className="panel">
      <header>
        <h2>Vault health</h2>
        <p>Weak, reused, and exposed credential reports.</p>
      </header>
      <div className="stats">
        <div className="stat"><span>{breachReport.weakPasswords}</span><label>Weak</label></div>
        <div className="stat"><span>{breachReport.reusedPasswords}</span><label>Reused</label></div>
        <div className="stat"><span>{breachReport.exposedPasswords}</span><label>Exposed</label></div>
      </div>
      <div className="card">
        <button onClick={() => void runBreachCheck()} disabled={checking}>
          {checking ? "Checking HIBP…" : "Check data breaches (HIBP)"}
        </button>
        <p className="hint">Uses k-anonymity — only a SHA-1 prefix leaves this device.</p>
        {breachError && <p className="error">{breachError}</p>}
      </div>
      <div className="card list">
        {breachReport.items.length === 0 ? <p className="muted">No issues found.</p> : (
          <ul>{breachReport.items.map((i) => <li key={i.cipherId}><strong>{i.name}</strong> — {i.issues.join(", ")}</li>)}</ul>
        )}
      </div>
    </section>
  );
}

function TotpBadge({ secret }: { secret: string }) {
  const [code, setCode] = useState("------");

  useEffect(() => {
    void (async () => {
      setCode(await generateTotp(secret));
    })();
    const timer = window.setInterval(() => {
      void generateTotp(secret).then(setCode);
    }, 30_000);
    return () => window.clearInterval(timer);
  }, [secret]);

  return <code className="tag">TOTP {code}</code>;
}

function ImportView({
  token,
  symmetricKey,
  onRefresh,
}: {
  token: string;
  symmetricKey: Uint8Array;
  onRefresh: () => void;
}) {
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  async function handleFile(file: File) {
    setError("");
    setStatus("Importing…");
    try {
      const text = await file.text();
      const isJson = file.name.toLowerCase().endsWith(".json");
      const rows = isJson ? parseBitwardenJson(text) : parseBitwardenCsv(text);
      if (!rows.length) throw new Error("No items found in export file");
      const ciphers = await Promise.all(
        rows.map(async (row) => ({
          type: row.type === "secureNote" ? "secureNote" : row.type,
          name: row.name,
          notes: row.notes,
          folderName: row.folder,
          favorite: row.favorite,
          reprompt: row.reprompt,
          encryptedData: await encryptJsonBrowser(symmetricKey, bitwardenRowsToCipherData(row)),
        })),
      );
      const folders = [...new Set(rows.map((r) => r.folder).filter(Boolean))] as string[];
      const result = await api<{ imported: number }>("/api/vault/import", {
        method: "POST",
        body: JSON.stringify({ folders, ciphers }),
      }, token);
      setStatus(`Imported ${result.imported} items from Bitwarden ${isJson ? "JSON" : "CSV"} export.`);
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
      setStatus("");
    }
  }

  return (
    <section className="panel">
      <header><h2>Import from Bitwarden</h2><p>Upload an unencrypted Bitwarden CSV or JSON export. Items are encrypted locally before upload.</p></header>
      <div className="card">
        <label>
          Bitwarden export file
          <input
            type="file"
            accept=".csv,.json,text/csv,application/json"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleFile(file);
            }}
          />
        </label>
        {status && <p className="success">{status}</p>}
        {error && <p className="error">{error}</p>}
        <p className="hint">Export from Bitwarden: Tools → Export vault → unencrypted CSV or JSON.</p>
      </div>
    </section>
  );
}

function ExportView({
  ciphers,
  folders,
}: {
  ciphers: Array<EncryptedCipher & { data: CipherData }>;
  folders: SyncResponse["folders"];
}) {
  function download(filename: string, content: string, mime: string) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  const plainCiphers = ciphers.map((cipher) => ({
    id: cipher.id,
    type: cipher.type,
    name: cipher.name,
    notes: cipher.notes,
    folderId: cipher.folderId,
    organizationId: cipher.organizationId,
    favorite: cipher.favorite,
    reprompt: cipher.reprompt,
    data: cipher.data,
    createdAt: cipher.createdAt,
    updatedAt: cipher.updatedAt,
  }));

  return (
    <section className="panel">
      <header><h2>Export vault</h2><p>Download decrypted exports for backup or migration. Handle files carefully.</p></header>
      <div className="card">
        <button onClick={() => download("omnisecure-export.csv", exportBitwardenCsv(plainCiphers, folders), "text/csv")}>
          Export Bitwarden CSV
        </button>
        <button onClick={() => download("omnisecure-export.json", exportBitwardenJson(plainCiphers, folders), "application/json")}>
          Export Bitwarden JSON
        </button>
        <p className="hint">{plainCiphers.length} decrypted items will be written to the downloaded file.</p>
      </div>
    </section>
  );
}

function OrgsView({
  token,
  organizations,
  onRefresh,
}: {
  token: string;
  organizations: SyncResponse["organizations"];
  onRefresh: () => void;
}) {
  const [name, setName] = useState("");
  const [identifier, setIdentifier] = useState("");
  const [orgId, setOrgId] = useState(organizations[0]?.id ?? "");
  const [status, setStatus] = useState("");
  const [ssoIssuer, setSsoIssuer] = useState("");
  const [ssoClientId, setSsoClientId] = useState("");
  const [ssoMetadataUrl, setSsoMetadataUrl] = useState("");
  const [scimToken, setScimToken] = useState("");

  async function createOrg() {
    await api("/api/organizations", {
      method: "POST",
      body: JSON.stringify({ name, identifier }),
    }, token);
    setName("");
    setIdentifier("");
    onRefresh();
  }

  async function exportAudit(format: "ndjson" | "csv") {
    if (!orgId) return;
    const response = await fetch(`${import.meta.env.VITE_API_URL ?? "http://localhost:8787"}/api/organizations/${orgId}/events/export?format=${format}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `omnisecure-audit-${orgId}.${format === "csv" ? "csv" : "ndjson"}`;
    anchor.click();
    URL.revokeObjectURL(url);
    setStatus(`Exported ${format.toUpperCase()} audit log.`);
  }

  async function saveSso() {
    if (!orgId) return;
    await api(`/api/organizations/${orgId}/idp`, {
      method: "PUT",
      body: JSON.stringify({
        provider: "oidc",
        issuer: ssoIssuer,
        clientId: ssoClientId,
        metadataUrl: ssoMetadataUrl,
        enabled: true,
      }),
    }, token);
    setStatus("SSO IdP configuration saved.");
  }

  async function createScimToken() {
    if (!orgId) return;
    const data = await api<{ token: string }>(`/api/organizations/${orgId}/scim-tokens`, { method: "POST" }, token);
    setScimToken(data.token);
    setStatus("SCIM provisioning token created.");
  }

  return (
    <section className="panel">
      <header><h2>Organizations</h2><p>Team vaults, collections, and SIEM-ready audit exports.</p></header>
      <div className="grid two">
        <div className="card">
          <h3>Create organization</h3>
          <label>Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label>Identifier<input value={identifier} onChange={(e) => setIdentifier(e.target.value)} placeholder="omnitender" /></label>
          <button onClick={() => void createOrg()} disabled={!name || !identifier}>Create</button>
        </div>
        <div className="card">
          <h3>SSO & SCIM</h3>
          <label>Organization
            <select value={orgId} onChange={(e) => setOrgId(e.target.value)}>
              {organizations.map((org) => <option key={org.id} value={org.id}>{org.name}</option>)}
            </select>
          </label>
          <label>OIDC issuer<input value={ssoIssuer} onChange={(e) => setSsoIssuer(e.target.value)} placeholder="https://login.microsoftonline.com/tenant/v2.0" /></label>
          <label>Client ID<input value={ssoClientId} onChange={(e) => setSsoClientId(e.target.value)} /></label>
          <label>Metadata URL<input value={ssoMetadataUrl} onChange={(e) => setSsoMetadataUrl(e.target.value)} /></label>
          <button onClick={() => void saveSso()} disabled={!orgId}>Save OIDC config</button>
          <button onClick={() => void createScimToken()} disabled={!orgId}>Generate SCIM token</button>
          {scimToken && <p className="success">SCIM token (copy now): <code>{scimToken}</code></p>}
          {orgId && <p className="hint">SSO login: <code>{`${import.meta.env.VITE_API_URL ?? ""}/api/sso/${orgId}/login`}</code></p>}
        </div>
      </div>
      <div className="card">
        <h3>Audit export</h3>
        <label>Organization
          <select value={orgId} onChange={(e) => setOrgId(e.target.value)}>
            {organizations.map((org) => <option key={org.id} value={org.id}>{org.name}</option>)}
          </select>
        </label>
        <button onClick={() => void exportAudit("ndjson")} disabled={!orgId}>Export NDJSON</button>
        <button onClick={() => void exportAudit("csv")} disabled={!orgId}>Export CSV</button>
        {status && <p className="success">{status}</p>}
      </div>
      <div className="card list">
        <h3>Your organizations</h3>
        {organizations.length === 0 ? <p className="muted">No organizations yet.</p> : (
          <ul>{organizations.map((org) => <li key={org.id}><strong>{org.name}</strong> <code>{org.identifier}</code></li>)}</ul>
        )}
      </div>
    </section>
  );
}

function EmergencyView({
  token,
  email,
  symmetricKey,
}: {
  token: string;
  email: string;
  symmetricKey: Uint8Array;
}) {
  const [granteeEmail, setGranteeEmail] = useState("");
  const [waitDays, setWaitDays] = useState("7");
  const [outgoing, setOutgoing] = useState<Array<Record<string, unknown>>>([]);
  const [incoming, setIncoming] = useState<Array<Record<string, unknown>>>([]);
  const [status, setStatus] = useState("");

  async function refresh() {
    const [mine, theirs] = await Promise.all([
      api<{ grants: Array<Record<string, unknown>> }>("/api/emergency-access", {}, token),
      api<{ grants: Array<Record<string, unknown>> }>("/api/emergency-access/incoming", {}, token),
    ]);
    setOutgoing(mine.grants);
    setIncoming(theirs.grants);
  }

  useEffect(() => {
    void refresh();
  }, [token]);

  async function createGrant() {
    await api("/api/emergency-access", {
      method: "POST",
      body: JSON.stringify({ granteeEmail, waitDays: Number(waitDays) }),
    }, token);
    setGranteeEmail("");
    setStatus("Emergency access invitation created.");
    refresh();
  }

  async function acceptGrant(id: string) {
    await api(`/api/emergency-access/${id}/accept`, { method: "POST" }, token);
    setStatus("Emergency access accepted.");
    refresh();
  }

  async function storeVaultKey(grantId: string) {
    const encryptedVaultKey = await encryptJsonBrowser(symmetricKey, { key: "vault-symmetric-key" });
    await api(`/api/emergency-access/${grantId}/vault-key`, {
      method: "PUT",
      body: JSON.stringify({ encryptedVaultKey }),
    }, token);
    setStatus("Encrypted vault key uploaded for grantee recovery.");
    refresh();
  }

  async function initiateRecovery(id: string) {
    await api(`/api/emergency-access/${id}/initiate`, { method: "POST" }, token);
    setStatus("Recovery initiated — waiting period started.");
    refresh();
  }

  async function claimVaultKey(id: string) {
    const data = await api<{ encryptedVaultKey: { iv: string; data: string } }>(`/api/emergency-access/${id}/vault-key`, {}, token);
    setStatus(`Vault key material ready (${data.encryptedVaultKey.iv.slice(0, 8)}…). Decrypt locally with grantor's shared secret.`);
  }

  return (
    <section className="panel">
      <header><h2>Emergency access</h2><p>Designate a trusted contact who can request vault access after a waiting period.</p></header>
      <div className="card">
        <label>Grantee email<input type="email" value={granteeEmail} onChange={(e) => setGranteeEmail(e.target.value)} /></label>
        <label>Wait days<input type="number" min={1} value={waitDays} onChange={(e) => setWaitDays(e.target.value)} /></label>
        <button onClick={() => void createGrant()} disabled={!granteeEmail}>Invite contact</button>
        {status && <p className="success">{status}</p>}
      </div>
      <div className="grid two">
        <div className="card list">
          <h3>Outgoing ({email})</h3>
          <ul>
            {outgoing.map((grant) => (
              <li key={String(grant.id)}>
                <strong>{String(grant.grantee_email)}</strong> — {String(grant.status)}
                <button onClick={() => void storeVaultKey(String(grant.id))}>Upload vault key</button>
              </li>
            ))}
          </ul>
        </div>
        <div className="card list">
          <h3>Incoming invitations</h3>
          {incoming.length === 0 ? <p className="muted">No invitations.</p> : (
            <ul>
              {incoming.map((grant) => (
                <li key={String(grant.id)}>
                  <strong>{String(grant.grantor_email ?? grant.grantor_user_id)}</strong> — {String(grant.status)}
                  {grant.status === "pending" && (
                    <button onClick={() => void acceptGrant(String(grant.id))}>Accept</button>
                  )}
                  {grant.status === "accepted" && (
                    <button onClick={() => void initiateRecovery(String(grant.id))}>Request access</button>
                  )}
                  {grant.status === "recovery_initiated" && (
                    <button onClick={() => void claimVaultKey(String(grant.id))}>Claim vault key</button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}

function SecurityView({
  token,
  email,
}: {
  token: string;
  email: string;
}) {
  const [credentials, setCredentials] = useState<Array<Record<string, unknown>>>([]);
  const [totpSecret, setTotpSecret] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [status, setStatus] = useState("");

  async function refresh() {
    const data = await api<{ credentials: Array<Record<string, unknown>> }>("/api/webauthn/credentials", {}, token);
    setCredentials(data.credentials);
  }

  useEffect(() => {
    void refresh();
  }, [token]);

  async function registerPasskey() {
    const { startRegistration } = await import("@simplewebauthn/browser");
    const options = await api<PublicKeyCredentialCreationOptionsJSON>("/api/webauthn/register/options", {
      method: "POST",
      body: JSON.stringify({ name: "Primary passkey" }),
    }, token);
    const response = await startRegistration({ optionsJSON: options });
    await api("/api/webauthn/register/verify", {
      method: "POST",
      body: JSON.stringify({ response, name: "Primary passkey" }),
    }, token);
    setStatus("Passkey registered.");
    refresh();
  }

  async function setupTotp() {
    const data = await api<{ secret: string; otpauthUrl: string }>("/api/auth/totp/setup", { method: "POST" }, token);
    setTotpSecret(data.secret);
    setStatus(`Scan in OmniAuth: ${data.otpauthUrl}`);
  }

  async function enableTotp() {
    await api("/api/auth/totp/enable", {
      method: "POST",
      body: JSON.stringify({ code: totpCode }),
    }, token);
    setStatus("Account 2FA enabled.");
  }

  return (
    <section className="panel">
      <header><h2>Security</h2><p>Passkeys, authenticator 2FA, and account hardening.</p></header>
      <div className="grid two">
        <div className="card">
          <h3>Passkeys ({email})</h3>
          <button onClick={() => void registerPasskey()}>Register passkey</button>
          <ul>{credentials.map((cred) => <li key={String(cred.id)}>{String(cred.name)} — {String(cred.credential_id).slice(0, 12)}…</li>)}</ul>
        </div>
        <div className="card">
          <h3>Authenticator 2FA</h3>
          <button onClick={() => void setupTotp()}>Generate TOTP secret</button>
          {totpSecret && <code className="mono">{totpSecret}</code>}
          <label>Verification code<input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} maxLength={6} /></label>
          <button onClick={() => void enableTotp()} disabled={!totpCode}>Enable 2FA</button>
        </div>
      </div>
      {status && <p className="success">{status}</p>}
    </section>
  );
}
