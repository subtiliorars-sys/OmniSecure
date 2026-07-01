import {
  filterLoginsForHost,
  getSession,
  type DecryptedLogin,
} from "./shared/storage.js";
import { loadDecryptedLogins } from "./shared/vault.js";

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  void (async () => {
    if (message.type === "getMatches") {
      const session = await getSession();
      if (!session?.unlockedKey) {
        sendResponse({ matches: [] as DecryptedLogin[] });
        return;
      }
      const logins = await loadDecryptedLogins(session);
      const matches = filterLoginsForHost(logins, message.hostname as string);
      sendResponse({ matches });
      return;
    }

    if (message.type === "autofill") {
      sendResponse({ ok: true });
    }
  })();
  return true;
});

chrome.action.onClicked?.addListener(() => {
  // popup handles UI
});
