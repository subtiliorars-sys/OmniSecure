import type { FastifyInstance } from "fastify";
import { v4 as uuid } from "uuid";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { generateAccessToken, hashToken } from "@omnisecure/crypto";
import type { AppDatabase } from "../db/schema.js";
import { getUserId, nowIso } from "../lib/utils.js";
import { serverConfig } from "../lib/config.js";
import { webauthnUserHandle } from "../lib/webauthn-utils.js";

function saveChallenge(
  db: AppDatabase,
  params: { userId?: string; email?: string; challenge: string; type: "registration" | "authentication" },
): void {
  db.prepare(`
    INSERT INTO webauthn_challenges (id, user_id, email, challenge, type, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    uuid(),
    params.userId ?? null,
    params.email?.toLowerCase() ?? null,
    params.challenge,
    params.type,
    new Date(Date.now() + 5 * 60_000).toISOString(),
    nowIso(),
  );
}

function loadChallenge(db: AppDatabase, challenge: string, type: "registration" | "authentication"): Record<string, unknown> | null {
  const row = db.prepare(`
    SELECT * FROM webauthn_challenges
    WHERE challenge = ? AND type = ? AND expires_at > ?
  `).get(challenge, type, nowIso()) as Record<string, unknown> | undefined;
  if (!row) return null;
  db.prepare("DELETE FROM webauthn_challenges WHERE id = ?").run(row.id);
  return row;
}

export async function webauthnRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.post<{ Body: { name?: string } }>(
    "/register/options",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const user = db.prepare("SELECT email FROM users WHERE id = ?").get(userId) as { email: string } | undefined;
      if (!user) return reply.code(404).send({ code: "not_found", message: "User not found" });

      const existing = db.prepare(`
        SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ?
      `).all(userId) as Array<Record<string, unknown>>;

      const options = await generateRegistrationOptions({
        rpName: serverConfig.webauthn.rpName,
        rpID: serverConfig.webauthn.rpId,
        userID: webauthnUserHandle(user.email),
        userName: user.email,
        userDisplayName: request.body.name ?? user.email,
        attestationType: "none",
        excludeCredentials: existing.map((cred) => ({
          id: String(cred.credential_id),
          transports: cred.transports ? JSON.parse(String(cred.transports)) : undefined,
        })),
      });

      saveChallenge(db, { userId, challenge: options.challenge, type: "registration" });
      return reply.send(options);
    },
  );

  app.post<{ Body: { response: RegistrationResponseJSON; name?: string } }>(
    "/register/verify",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const clientData = JSON.parse(
        Buffer.from(request.body.response.response.clientDataJSON, "base64url").toString(),
      ) as { challenge: string };
      const challengeRow = loadChallenge(db, clientData.challenge, "registration");
      if (!challengeRow || String(challengeRow.user_id) !== userId) {
        return reply.code(400).send({ code: "invalid_challenge", message: "Registration challenge expired" });
      }

      const verification = await verifyRegistrationResponse({
        response: request.body.response,
        expectedChallenge: clientData.challenge,
        expectedOrigin: serverConfig.webauthn.origin,
        expectedRPID: serverConfig.webauthn.rpId,
      });

      if (!verification.verified || !verification.registrationInfo) {
        return reply.code(400).send({ code: "verification_failed", message: "Passkey registration failed" });
      }

      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
      const id = uuid();
      const ts = nowIso();
      db.prepare(`
        INSERT INTO webauthn_credentials (
          id, user_id, credential_id, public_key, counter, transports, name, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        userId,
        credential.id,
        Buffer.from(credential.publicKey).toString("base64url"),
        credential.counter,
        JSON.stringify(credential.transports ?? []),
        request.body.name ?? "Passkey",
        ts,
      );

      return reply.send({
        verified: true,
        credentialId: credential.id,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
      });
    },
  );

  app.post<{ Body: { email?: string } }>("/login/options", async (request, reply) => {
    const email = request.body.email?.toLowerCase();
    let credentials: Array<Record<string, unknown>> = [];

    if (email) {
      const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email) as { id: string } | undefined;
      if (user) {
        credentials = db.prepare(`
          SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ?
        `).all(user.id) as Array<Record<string, unknown>>;
      }
    }

    const options = await generateAuthenticationOptions({
      rpID: serverConfig.webauthn.rpId,
      allowCredentials: credentials.map((cred) => ({
        id: String(cred.credential_id),
        transports: cred.transports ? JSON.parse(String(cred.transports)) : undefined,
      })),
    });

    saveChallenge(db, { email, challenge: options.challenge, type: "authentication" });
    return reply.send(options);
  });

  app.post<{ Body: { response: AuthenticationResponseJSON } }>("/login/verify", async (request, reply) => {
    const clientData = JSON.parse(
      Buffer.from(request.body.response.response.clientDataJSON, "base64url").toString(),
    ) as { challenge: string };
    loadChallenge(db, clientData.challenge, "authentication");

    const credentialId = request.body.response.id;
    const stored = db.prepare(`
      SELECT wc.*, u.email, u.id AS user_id, u.name, u.premium,
        u.stretched_master_key, u.encrypted_symmetric_key_iv, u.encrypted_symmetric_key_data,
        u.public_key, u.encrypted_private_key_iv, u.encrypted_private_key_data
      FROM webauthn_credentials wc
      JOIN users u ON u.id = wc.user_id
      WHERE wc.credential_id = ?
    `).get(credentialId) as Record<string, unknown> | undefined;

    if (!stored) {
      return reply.code(401).send({ code: "invalid_credentials", message: "Unknown passkey" });
    }

    const verification = await verifyAuthenticationResponse({
      response: request.body.response,
      expectedChallenge: clientData.challenge,
      expectedOrigin: serverConfig.webauthn.origin,
      expectedRPID: serverConfig.webauthn.rpId,
      credential: {
        id: String(stored.credential_id),
        publicKey: Buffer.from(String(stored.public_key), "base64url"),
        counter: Number(stored.counter),
        transports: stored.transports ? JSON.parse(String(stored.transports)) : undefined,
      },
    });

    if (!verification.verified) {
      return reply.code(401).send({ code: "verification_failed", message: "Passkey verification failed" });
    }

    db.prepare("UPDATE webauthn_credentials SET counter = ? WHERE id = ?").run(
      verification.authenticationInfo.newCounter,
      stored.id,
    );

    const userId = String(stored.user_id);
    const ts = nowIso();
    const token = generateAccessToken();
    db.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(uuid(), userId, hashToken(token), new Date(Date.now() + 7 * 86400000).toISOString(), ts);

    const jwt = app.jwt.sign({ sub: userId, email: String(stored.email) }, { expiresIn: "7d" });
    return reply.send({
      token: jwt,
      apiToken: token,
      user: {
        id: userId,
        email: stored.email,
        name: stored.name,
        premium: Boolean(stored.premium),
      },
      userKeys: {
        stretchedMasterKey: stored.stretched_master_key,
        encryptedSymmetricKey: {
          iv: stored.encrypted_symmetric_key_iv,
          data: stored.encrypted_symmetric_key_data,
        },
        publicKey: stored.public_key,
        encryptedPrivateKey: {
          iv: stored.encrypted_private_key_iv,
          data: stored.encrypted_private_key_data,
        },
      },
      passkey: true,
    });
  });

  app.get("/credentials", { preHandler: [app.authenticate] }, async (request, reply) => {
    const userId = getUserId(request);
    const credentials = db.prepare(`
      SELECT id, credential_id, name, counter, created_at FROM webauthn_credentials WHERE user_id = ?
    `).all(userId);
    return reply.send({ credentials });
  });

  app.delete<{ Params: { id: string } }>(
    "/credentials/:id",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const result = db.prepare(`
        DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?
      `).run(request.params.id, userId);
      if (result.changes === 0) {
        return reply.code(404).send({ code: "not_found", message: "Credential not found" });
      }
      return reply.code(204).send();
    },
  );
}
