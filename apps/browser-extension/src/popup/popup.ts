import { unlockSymmetricKeyBrowser } from "@omnisecure/crypto/browser";
import {
  DEFAULT_API,
  filterLoginsForHost,
  getSession,
  saveSession,
  type DecryptedLogin,
  type ExtensionSession,
} from "../shared/storage.js";
import { loadDecryptedLogins } from "../shared/vault.js";

const app = document.getElementById("app")!;

async function render(): Promise<void> {
  const session = await getSession();
  if (!session) {
    renderLogin();
    return;
  }
  if (!session.unlockedKey) {
    renderUnlock(session);
    return;
  }
  await renderMatches(session);
}

function renderLogin(): void {
  app.innerHTML = `
    <div class="wrap">
      <h1><span class="mark">OS</span> OmniSecure</h1>
      <p class="sub">Sign in to autofill from your vault</p>
      <label>API URL<input id="api" value="${DEFAULT_API}" /></label>
      <label>Email<input id="email" type="email" placeholder="you@omnitender.us" /></label>
      <label>Master password<input id="password" type="password" /></label>
      <p class="error" id="err"></p>
      <button id="signin">Sign in & unlock</button>
    </div>`;

  document.getElementById("signin")!.addEventListener("click", async () => {
    const apiUrl = (document.getElementById("api") as HTMLInputElement).value.trim();
    const email = (document.getElementById("email") as HTMLInputElement).value.trim();
    const password = (document.getElementById("password") as HTMLInputElement).value;
    const err = document.getElementById("err")!;
    err.textContent = "";
    try {
      const res = await fetch(`${apiUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, masterPassword: password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message ?? "Login failed");
      const key = await unlockSymmetricKeyBrowser(password, email, data.userKeys);
      const session: ExtensionSession = {
        apiUrl,
        token: data.token,
        email,
        userKeys: data.userKeys,
        unlockedKey: btoa(String.fromCharCode(...key)),
      };
      await saveSession(session);
      await render();
    } catch (e) {
      err.textContent = e instanceof Error ? e.message : "Login failed";
    }
  });
}

function renderUnlock(session: ExtensionSession): void {
  app.innerHTML = `
    <div class="wrap">
      <h1><span class="mark">OS</span> Unlock vault</h1>
      <p class="sub">${session.email}</p>
      <label>Master password<input id="password" type="password" /></label>
      <p class="error" id="err"></p>
      <button id="unlock">Unlock</button>
      <button class="ghost" id="logout">Sign out</button>
    </div>`;

  document.getElementById("unlock")!.addEventListener("click", async () => {
    const password = (document.getElementById("password") as HTMLInputElement).value;
    const err = document.getElementById("err")!;
    try {
      const key = await unlockSymmetricKeyBrowser(password, session.email, session.userKeys);
      await saveSession({ ...session, unlockedKey: btoa(String.fromCharCode(...key)) });
      await render();
    } catch {
      err.textContent = "Invalid master password";
    }
  });

  document.getElementById("logout")!.addEventListener("click", async () => {
    await saveSession(null);
    await render();
  });
}

async function renderMatches(session: ExtensionSession): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const hostname = tab?.url ? new URL(tab.url).hostname : "";
  let matches: DecryptedLogin[] = [];
  let error = "";

  try {
    const logins = await loadDecryptedLogins(session);
    matches = filterLoginsForHost(logins, hostname);
  } catch (e) {
    error = e instanceof Error ? e.message : "Failed to load vault";
  }

  app.innerHTML = `
    <div class="wrap">
      <h1><span class="mark">OS</span> OmniSecure</h1>
      <p class="sub">${hostname || "No active tab"}</p>
      ${error ? `<p class="error">${error}</p>` : ""}
      <div id="matches"></div>
      <button class="ghost" id="lock">Lock vault</button>
    </div>`;

  const list = document.getElementById("matches")!;
  if (!matches.length) {
    list.innerHTML = `<p class="sub">No logins match this site.</p>`;
  } else {
    for (const match of matches) {
      const div = document.createElement("div");
      div.className = "match";
      div.innerHTML = `<strong>${match.name}</strong><span>${match.username ?? "No username"}</span>`;
      const btn = document.createElement("button");
      btn.textContent = "Autofill";
      btn.addEventListener("click", async () => {
        if (!tab?.id) return;
        await chrome.tabs.sendMessage(tab.id, {
          type: "fillLogin",
          username: match.username,
          password: match.password,
        });
        window.close();
      });
      div.appendChild(btn);
      list.appendChild(div);
    }
  }

  document.getElementById("lock")!.addEventListener("click", async () => {
    await saveSession({ ...session, unlockedKey: undefined });
    await render();
  });
}

async function lockVaultKey(): Promise<void> {
  const session = await getSession();
  if (!session?.unlockedKey) return;
  await saveSession({ ...session, unlockedKey: undefined });
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") void lockVaultKey();
});
window.addEventListener("pagehide", () => {
  void lockVaultKey();
});

void render();
