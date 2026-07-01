import { useEffect, useState } from "react";
import { decryptJsonBrowser } from "@omnisecure/crypto/browser";
import { readSendKeyFromLocation, sendKeyFromPassword } from "./send-utils";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8787";

export function SendReceivePage({ accessId }: { accessId: string }) {
  const [password, setPassword] = useState("");
  const [needsPassword, setNeedsPassword] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void openSend();
  }, [accessId]);

  async function openSend(sendPassword?: string) {
    setLoading(true);
    setError("");
    try {
      const metaResponse = await fetch(`${API_BASE}/api/send/${accessId}`);
      const meta = await metaResponse.json() as Record<string, unknown>;
      if (!metaResponse.ok) {
        throw new Error(String(meta.message ?? "Send not found"));
      }

      if (meta.passwordProtected && !sendPassword) {
        setNeedsPassword(true);
        setLoading(false);
        return;
      }

      let payload = meta.encryptedPayload as { iv: string; data: string } | null;
      let sendKey = readSendKeyFromLocation(window.location);

      if (meta.passwordProtected && sendPassword) {
        const unlockResponse = await fetch(`${API_BASE}/api/send/${accessId}/unlock`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: sendPassword }),
        });
        const unlocked = await unlockResponse.json() as Record<string, unknown>;
        if (!unlockResponse.ok) {
          throw new Error(String(unlocked.message ?? "Incorrect Send password"));
        }
        payload = unlocked.encryptedPayload as { iv: string; data: string };
        sendKey = await sendKeyFromPassword(sendPassword, accessId);
      }

      if (!payload || !sendKey) {
        throw new Error("Missing decryption key — open the full Send link including the #k= fragment");
      }

      const plaintext = await decryptJsonBrowser<string>(sendKey, payload);
      setMessage(plaintext);
      setNeedsPassword(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to open Send");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="brand large">
          <div className="brand-mark">OS</div>
          <div>
            <h1>OmniSecure Send</h1>
            <p>Encrypted message shared with you</p>
          </div>
        </div>
        {loading && <p className="muted">Opening secure message…</p>}
        {needsPassword && (
          <form onSubmit={(e) => { e.preventDefault(); void openSend(password); }}>
            <label>
              Send password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
            </label>
            <button type="submit">Unlock</button>
          </form>
        )}
        {error && <p className="error">{error}</p>}
        {message && (
          <div className="card">
            <pre className="mono">{message}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
