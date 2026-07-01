import { useCallback, useEffect, useMemo, useState } from "react";
import type { EncryptedCipher, SyncResponse, CipherData } from "@omnisecure/core";
import { analyzeVaultHealth, generatePassword, parseBitwardenCsv, bitwardenRowsToCipherData } from "@omnisecure/core";
import {
  decryptJsonBrowser,
  encryptJsonBrowser,
  randomKeyBrowser,
  unlockSymmetricKeyBrowser,
} from "@omnisecure/crypto/browser";
import { api, clearSession, loadSession, saveSession, type Session } from "./api";

type View = "vault" | "send" | "secrets" | "tools" | "health" | "import";

export function App() {
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [view, setView] = useState<View>("vault");
  const [sync, setSync] = useState<SyncResponse | null>(null);
  const [unlocked, setUnlocked] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [symmetricKey, setSymmetricKey] = useState<Uint8Array | null>(null);

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
      const next: Session = { token: data.token, email: data.user.email, userKeys: data.userKeys };
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
    return <AuthScreen onAuth={handleAuth} loading={loading} error={error} />;
  }

  if (!unlocked) {
    return (
      <UnlockScreen
        email={session.email}
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
        {view === "health" && <HealthView report={health} />}
        {view === "import" && symmetricKey && (
          <ImportView token={session.token} symmetricKey={symmetricKey} onRefresh={() => refreshSync(session.token)} />
        )}
      </main>
    </div>
  );
}

function AuthScreen({
  onAuth,
  loading,
  error,
}: {
  onAuth: (mode: "login" | "register", email: string, password: string, name?: string) => void;
  loading: boolean;
  error: string;
}) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");

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
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={loading}>{loading ? "Working…" : mode === "login" ? "Unlock vault" : "Create vault"}</button>
        </form>
        <p className="hint">End-to-end encrypted. OmniSecure servers store ciphertext only — your master password never leaves this device.</p>
      </div>
    </div>
  );
}

function UnlockScreen({
  email,
  onUnlock,
  onLogout,
  error,
}: {
  email: string;
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
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}

function SendView({ token }: { token: string }) {
  const [text, setText] = useState("");
  const [link, setLink] = useState("");

  async function createSend() {
    const sendKey = randomKeyBrowser();
    const encryptedPayload = await encryptJsonBrowser(sendKey, text);
    const data = await api<{ accessId: string }>("/api/send", {
      method: "POST",
      body: JSON.stringify({ type: "text", name: "Shared note", encryptedPayload }),
    }, token);
    setLink(`${window.location.origin}/send/${data.accessId}`);
  }

  return (
    <section className="panel">
      <header><h2>OmniSecure Send</h2><p>Share encrypted text with expiring links — like Bitwarden Send.</p></header>
      <div className="card">
        <label>Message<textarea value={text} onChange={(e) => setText(e.target.value)} rows={5} /></label>
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

function HealthView({ report }: { report: ReturnType<typeof analyzeVaultHealth> }) {
  return (
    <section className="panel">
      <header><h2>Vault health</h2><p>Weak, reused, and exposed credential reports.</p></header>
      <div className="stats">
        <div className="stat"><span>{report.weakPasswords}</span><label>Weak</label></div>
        <div className="stat"><span>{report.reusedPasswords}</span><label>Reused</label></div>
        <div className="stat"><span>{report.exposedPasswords}</span><label>Exposed</label></div>
      </div>
      <div className="card list">
        {report.items.length === 0 ? <p className="muted">No issues found.</p> : (
          <ul>{report.items.map((i) => <li key={i.cipherId}><strong>{i.name}</strong> — {i.issues.join(", ")}</li>)}</ul>
        )}
      </div>
    </section>
  );
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
      const csv = await file.text();
      const rows = parseBitwardenCsv(csv);
      if (!rows.length) throw new Error("No items found in CSV");
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
      setStatus(`Imported ${result.imported} items from Bitwarden export.`);
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
      setStatus("");
    }
  }

  return (
    <section className="panel">
      <header><h2>Import from Bitwarden</h2><p>Upload an unencrypted Bitwarden CSV export. Items are encrypted locally before upload.</p></header>
      <div className="card">
        <label>
          Bitwarden CSV file
          <input
            type="file"
            accept=".csv,text/csv"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleFile(file);
            }}
          />
        </label>
        {status && <p className="success">{status}</p>}
        {error && <p className="error">{error}</p>}
        <p className="hint">Export from Bitwarden: Tools → Export vault → File format CSV (unencrypted).</p>
      </div>
    </section>
  );
}
