const BADGE_ID = "omnisecure-autofill-root";

function findUsernameField(): HTMLInputElement | null {
  const selectors = [
    'input[autocomplete="username"]',
    'input[type="email"]',
    'input[name="username"]',
    'input[name="email"]',
    'input[id="username"]',
    'input[id="email"]',
  ];
  for (const sel of selectors) {
    const el = document.querySelector<HTMLInputElement>(sel);
    if (el && isVisible(el)) return el;
  }
  return null;
}

function findPasswordField(): HTMLInputElement | null {
  const el = document.querySelector<HTMLInputElement>('input[type="password"]');
  return el && isVisible(el) ? el : null;
}

function isVisible(el: HTMLElement): boolean {
  const style = window.getComputedStyle(el);
  return style.display !== "none" && style.visibility !== "hidden" && el.offsetParent !== null;
}

function setNativeValue(el: HTMLInputElement, value: string): void {
  const proto = Object.getPrototypeOf(el);
  const desc = Object.getOwnPropertyDescriptor(proto, "value");
  if (desc?.set) desc.set.call(el, value);
  else el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

function fillCredentials(username: string | undefined, password: string | undefined): void {
  const userField = findUsernameField();
  const passField = findPasswordField();
  if (userField && username) setNativeValue(userField, username);
  if (passField && password) setNativeValue(passField, password);
}

function removeBadge(): void {
  document.getElementById(BADGE_ID)?.remove();
}

function showBadge(count: number, onPick: (index: number) => void, matches: Array<{ name: string; username?: string }>): void {
  removeBadge();
  if (count === 0) return;

  const root = document.createElement("div");
  root.id = BADGE_ID;
  root.className = "omnisecure-badge";
  root.innerHTML = `<button type="button" class="omnisecure-badge-btn" aria-label="OmniSecure autofill">
    <span class="omnisecure-badge-mark">OS</span>
    <span>${count} login${count === 1 ? "" : "s"}</span>
  </button>`;

  const list = document.createElement("ul");
  list.className = "omnisecure-badge-list";
  list.hidden = true;

  matches.forEach((match, index) => {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = `${match.name}${match.username ? ` (${match.username})` : ""}`;
    btn.addEventListener("click", () => {
      onPick(index);
      list.hidden = true;
    });
    li.appendChild(btn);
    list.appendChild(li);
  });

  root.querySelector(".omnisecure-badge-btn")?.addEventListener("click", () => {
    if (count === 1) {
      onPick(0);
      return;
    }
    list.hidden = !list.hidden;
  });

  root.appendChild(list);
  document.documentElement.appendChild(root);
}

function injectStyles(): void {
  if (document.getElementById("omnisecure-content-css")) return;
  const link = document.createElement("link");
  link.id = "omnisecure-content-css";
  link.rel = "stylesheet";
  link.href = chrome.runtime.getURL("content.css");
  document.head.appendChild(link);
}

async function init(): Promise<void> {
  injectStyles();
  const hostname = window.location.hostname;
  if (!hostname || hostname === "localhost" && window.location.pathname.includes("popup")) return;

  const response = await chrome.runtime.sendMessage({ type: "getMatches", hostname });
  const matches = (response?.matches ?? []) as Array<{ name: string; username?: string; password?: string }>;
  if (!matches.length) return;

  showBadge(matches.length, (index) => {
    const match = matches[index];
    if (!match) return;
    fillCredentials(match.username, match.password);
    removeBadge();
  }, matches);
}

void init();

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "fillLogin") {
    fillCredentials(message.username as string | undefined, message.password as string | undefined);
    removeBadge();
  }
});
