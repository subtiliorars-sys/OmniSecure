import type { Cipher, LoginCipherData, VaultHealthReport } from "./types.js";
import { scorePasswordStrength } from "./generators.js";

export function analyzeVaultHealth(ciphers: Cipher[]): VaultHealthReport {
  const loginItems = ciphers.filter((c) => c.type === "login");
  const passwordMap = new Map<string, string[]>();
  const items: VaultHealthReport["items"] = [];

  let weakPasswords = 0;
  let reusedPasswords = 0;

  for (const cipher of loginItems) {
    const data = cipher.data as LoginCipherData;
    const password = data.password ?? "";
    const issues: string[] = [];

    if (!password) {
      issues.push("missing_password");
    } else {
      const strength = scorePasswordStrength(password);
      if (strength.score <= 1) {
        weakPasswords++;
        issues.push("weak_password");
      }
      const existing = passwordMap.get(password) ?? [];
      existing.push(cipher.id);
      passwordMap.set(password, existing);
    }

    if (issues.length) {
      items.push({ cipherId: cipher.id, name: cipher.name, issues });
    }
  }

  for (const ids of passwordMap.values()) {
    if (ids.length > 1) {
      reusedPasswords += ids.length;
      for (const cipherId of ids) {
        const entry = items.find((i) => i.cipherId === cipherId);
        if (entry && !entry.issues.includes("reused_password")) {
          entry.issues.push("reused_password");
        } else if (!entry) {
          const cipher = loginItems.find((c) => c.id === cipherId);
          items.push({
            cipherId,
            name: cipher?.name ?? cipherId,
            issues: ["reused_password"],
          });
        }
      }
    }
  }

  return {
    weakPasswords,
    reusedPasswords,
    exposedPasswords: 0,
    unsecureWebsites: 0,
    items,
  };
}
