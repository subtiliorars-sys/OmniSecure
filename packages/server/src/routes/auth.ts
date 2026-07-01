import type { FastifyInstance } from "fastify";
import { v4 as uuid } from "uuid";
import {
  generateAccessToken,
  generateUserKeys,
  hashMasterPassword,
  hashToken,
  verifyTotp,
} from "@omnisecure/crypto";
import type { AppDatabase } from "../db/schema.js";
import { getUserId, nowIso } from "../lib/utils.js";

interface RegisterBody {
  email: string;
  name?: string;
  masterPassword: string;
}

interface LoginBody {
  email: string;
  masterPassword: string;
  totpCode?: string;
}

export async function authRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.post<{ Body: RegisterBody }>("/register", async (request, reply) => {
    const { email, name, masterPassword } = request.body;
    if (!email || !masterPassword) {
      return reply.code(400).send({ code: "invalid_request", message: "Email and master password required" });
    }

    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email.toLowerCase());
    if (existing) {
      return reply.code(409).send({ code: "user_exists", message: "User already exists" });
    }

    const id = uuid();
    const ts = nowIso();
    const { masterPasswordHash, userKeys } = generateUserKeys(masterPassword, email);

    db.prepare(`
      INSERT INTO users (
        id, email, name, master_password_hash,
        encrypted_symmetric_key_iv, encrypted_symmetric_key_data,
        stretched_master_key, public_key,
        encrypted_private_key_iv, encrypted_private_key_data,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      email.toLowerCase(),
      name ?? null,
      masterPasswordHash,
      userKeys.encryptedSymmetricKey.iv,
      userKeys.encryptedSymmetricKey.data,
      userKeys.stretchedMasterKey,
      userKeys.publicKey,
      userKeys.encryptedPrivateKey.iv,
      userKeys.encryptedPrivateKey.data,
      ts,
      ts,
    );

    const token = generateAccessToken();
    const sessionId = uuid();
    db.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(sessionId, id, hashToken(token), new Date(Date.now() + 7 * 86400000).toISOString(), ts);

    const jwt = app.jwt.sign({ sub: id, email: email.toLowerCase() }, { expiresIn: "7d" });
    return reply.send({
      token: jwt,
      apiToken: token,
      user: { id, email: email.toLowerCase(), name },
      userKeys,
    });
  });

  app.post<{ Body: LoginBody }>("/login", async (request, reply) => {
    const { email, masterPassword, totpCode } = request.body;
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email.toLowerCase()) as Record<string, unknown> | undefined;
    if (!user) {
      return reply.code(401).send({ code: "invalid_credentials", message: "Invalid credentials" });
    }

    const hash = hashMasterPassword(masterPassword, email);
    if (user.master_password_hash !== hash) {
      return reply.code(401).send({ code: "invalid_credentials", message: "Invalid credentials" });
    }

    if (user.totp_enabled && !verifyTotp(String(user.totp_secret), totpCode ?? "")) {
      return reply.code(401).send({ code: "invalid_2fa", message: "Invalid two-factor code" });
    }

    const id = String(user.id);
    const ts = nowIso();
    const token = generateAccessToken();
    db.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(uuid(), id, hashToken(token), new Date(Date.now() + 7 * 86400000).toISOString(), ts);

    const jwt = app.jwt.sign({ sub: id, email: email.toLowerCase() }, { expiresIn: "7d" });
    return reply.send({
      token: jwt,
      apiToken: token,
      user: {
        id,
        email: user.email,
        name: user.name,
        premium: Boolean(user.premium),
      },
      userKeys: {
        stretchedMasterKey: user.stretched_master_key,
        encryptedSymmetricKey: {
          iv: user.encrypted_symmetric_key_iv,
          data: user.encrypted_symmetric_key_data,
        },
        publicKey: user.public_key,
        encryptedPrivateKey: {
          iv: user.encrypted_private_key_iv,
          data: user.encrypted_private_key_data,
        },
      },
    });
  });

  app.get("/me", { preHandler: [app.authenticate] }, async (request, reply) => {
    const userId = getUserId(request);
    const user = db.prepare("SELECT id, email, name, premium, totp_enabled FROM users WHERE id = ?").get(userId);
    if (!user) return reply.code(404).send({ code: "not_found", message: "User not found" });
    return reply.send({ user });
  });
}
