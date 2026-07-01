import type { Cipher, LoginCipherData, VaultHealthReport } from "./types.js";
import { scorePasswordStrength } from "./generators.js";
import type { PwnedPasswordResult } from "./hibp.js";

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

export async function enrichVaultHealthWithBreaches(
  report: VaultHealthReport,
  ciphers: Cipher[],
  checkPassword: (password: string) => Promise<PwnedPasswordResult>,
): Promise<VaultHealthReport> {
  const loginItems = ciphers.filter((cipher) => cipher.type === "login");
  const checked = new Map<string, PwnedPasswordResult>();
  let exposedPasswords = 0;
  const items = [...report.items];

  for (const cipher of loginItems) {
    const password = (cipher.data as LoginCipherData).password ?? "";
    if (!password) continue;

    let result = checked.get(password);
    if (!result) {
      result = await checkPassword(password);
      checked.set(password, result);
    }

    if (!result.exposed) continue;
    exposedPasswords++;

    const existing = items.find((item) => item.cipherId === cipher.id);
    if (existing) {
      if (!existing.issues.includes("exposed_password")) {
        existing.issues.push("exposed_password");
      }
    } else {
      items.push({
        cipherId: cipher.id,
        name: cipher.name,
        issues: ["exposed_password"],
      });
    }
  }

  return {
    ...report,
    exposedPasswords,
    items,
  };
}
