const LOWER = "abcdefghijkmnopqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{}|:;,.<>?";

export interface PasswordOptions {
  length?: number;
  lowercase?: boolean;
  uppercase?: boolean;
  numbers?: boolean;
  symbols?: boolean;
  minNumbers?: number;
  minSymbols?: number;
  ambiguous?: boolean;
}

export function generatePassword(options: PasswordOptions = {}): string {
  const length = options.length ?? 20;
  const useLower = options.lowercase ?? true;
  const useUpper = options.uppercase ?? true;
  const useNumbers = options.numbers ?? true;
  const useSymbols = options.symbols ?? true;
  const minNumbers = options.minNumbers ?? 1;
  const minSymbols = options.minSymbols ?? 1;

  let charset = "";
  if (useLower) charset += LOWER;
  if (useUpper) charset += UPPER;
  if (useNumbers) charset += DIGITS;
  if (useSymbols) charset += SYMBOLS;
  if (!charset) charset = LOWER + UPPER + DIGITS;

  const required: string[] = [];
  if (useNumbers) {
    for (let i = 0; i < minNumbers; i++) {
      required.push(pick(DIGITS));
    }
  }
  if (useSymbols) {
    for (let i = 0; i < minSymbols; i++) {
      required.push(pick(SYMBOLS));
    }
  }

  const remaining = Math.max(length - required.length, 0);
  const chars = [...required];
  for (let i = 0; i < remaining; i++) {
    chars.push(pick(charset));
  }
  return shuffle(chars).join("");
}

const WORDS = [
  "apple", "river", "cloud", "stone", "light", "ember", "north", "spark",
  "cedar", "orbit", "maple", "delta", "forge", "pixel", "vault", "tiger",
  "ocean", "brave", "quiet", "swift", "coral", "frost", "amber", "lunar",
  "prism", "ridge", "solar", "vivid", "whale", "zenith", "anchor", "breeze",
];

export function generatePassphrase(wordCount = 6, separator = "-"): string {
  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(pickWord(WORDS));
  }
  return words.join(separator);
}

export function generateUsername(length = 12): string {
  const chars = LOWER + DIGITS;
  let result = pick(LOWER);
  for (let i = 1; i < length; i++) {
    result += pick(chars);
  }
  return result;
}

export function scorePasswordStrength(password: string): {
  score: 0 | 1 | 2 | 3 | 4;
  label: "weak" | "fair" | "good" | "strong" | "excellent";
  feedback: string[];
} {
  let score = 0;
  const feedback: string[] = [];

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;

  if (password.length < 12) feedback.push("Use at least 12 characters");
  if (!/[A-Z]/.test(password)) feedback.push("Add uppercase letters");
  if (!/\d/.test(password)) feedback.push("Add numbers");
  if (!/[^a-zA-Z0-9]/.test(password)) feedback.push("Add symbols");

  const labels = ["weak", "fair", "good", "strong", "excellent"] as const;
  const clamped = Math.min(score, 4) as 0 | 1 | 2 | 3 | 4;
  return { score: clamped, label: labels[clamped], feedback };
}

function pick(source: string): string {
  const index = crypto.getRandomValues(new Uint32Array(1))[0]! % source.length;
  return source[index]!;
}

function pickWord(words: string[]): string {
  const index = crypto.getRandomValues(new Uint32Array(1))[0]! % words.length;
  return words[index]!;
}

function shuffle<T>(items: T[]): T[] {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0]! % (i + 1);
    [copy[i], copy[j]] = [copy[j]!, copy[i]!];
  }
  return copy;
}
