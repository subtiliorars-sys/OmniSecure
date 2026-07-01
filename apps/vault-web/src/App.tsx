import { useCallback, useEffect, useMemo, useState } from "react";
import type { EncryptedCipher, SyncResponse, CipherData } from "@omnisecure/core";
import { analyzeVaultHealth, generatePassword, parseBitwardenCsv, bitwardenRowsToCipherData, parseBitwardenJson, enrichVaultHealthWithBreaches, checkPasswordPwned, generateTotp, exportBitwardenCsv, exportBitwardenJson } from "@omnisecure/core";
import {
  decryptJsonBrowser,
  encryptJsonBrowser,
  randomKeyBrowser,
  unlockSymmetricKeyBrowser,
} from "@omnisecure/crypto/browser";
import { api, clearSession, loadSession, saveSession, type Session } from "./api";
import { encodeSendKey, sendKeyFromPassword } from "./send-utils";

type View = "vault" | "send" | "secrets" | "tools" | "health" | "import" | "export" | "emergency" | "orgs";

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
          <button className={view === "export" ? "active" : ""} onClick={() => setView("export")}>Export</button>
          <button className={view === "orgs" ? "active" : ""} onClick={() => setView("orgs")}>Organizations</button>
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
        {view === "emergency" && (
          <EmergencyView token={session.token} email={session.email} />
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
                  {"totp" in c.data && Boolean((c.data as { totp?: string }).totp) && (
                    <TotpBadge secret={String((c.data as { totp?: string }).totp)} />
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

function EmergencyView({ token, email }: { token: string; email: string }) {
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
          <ul>{outgoing.map((grant) => <li key={String(grant.id)}><strong>{String(grant.grantee_email)}</strong> — {String(grant.status)}</li>)}</ul>
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
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}
