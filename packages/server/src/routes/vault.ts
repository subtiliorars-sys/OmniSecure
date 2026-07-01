import type { FastifyInstance } from "fastify";
import { v4 as uuid } from "uuid";
import type { EncryptedCipher, Folder, SyncResponse } from "@omnisecure/core";
import type { AppDatabase } from "../db/schema.js";
import { getUserId, nowIso } from "../lib/utils.js";

interface CipherBody {
  type: string;
  name: string;
  notes?: string;
  folderId?: string | null;
  organizationId?: string | null;
  collectionIds?: string[];
  favorite?: boolean;
  reprompt?: boolean;
  encryptedData: { iv: string; data: string };
}

export async function vaultRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.get("/sync", { preHandler: [app.authenticate] }, async (request, reply) => {
    const userId = getUserId(request);
    const user = db.prepare("SELECT id, email, name, premium FROM users WHERE id = ?").get(userId) as Record<string, unknown>;
    if (!user) return reply.code(404).send({ code: "not_found", message: "User not found" });

    const folders = db.prepare("SELECT * FROM folders WHERE user_id = ?").all(userId) as Array<Record<string, unknown>>;
    const ciphers = db.prepare("SELECT * FROM ciphers WHERE user_id = ?").all(userId) as Array<Record<string, unknown>>;
    const orgRows = db.prepare(`
      SELECT o.* FROM organizations o
      JOIN organization_users ou ON ou.organization_id = o.id
      WHERE ou.user_id = ?
    `).all(userId) as Array<Record<string, unknown>>;
    const collections = orgRows.length
      ? db.prepare(`
          SELECT c.* FROM collections c
          JOIN organizations o ON o.id = c.organization_id
          JOIN organization_users ou ON ou.organization_id = o.id
          WHERE ou.user_id = ?
        `).all(userId) as Array<Record<string, unknown>>
      : [];
    const sends = db.prepare("SELECT * FROM sends WHERE user_id = ? AND disabled = 0").all(userId) as Array<Record<string, unknown>>;

    const response: SyncResponse = {
      profile: {
        id: String(user.id),
        email: String(user.email),
        name: user.name ? String(user.name) : undefined,
        premium: Boolean(user.premium),
      },
      folders: folders.map(mapFolder),
      ciphers: ciphers.map(mapCipher),
      collections: collections.map((c) => ({
        id: String(c.id),
        organizationId: String(c.organization_id),
        name: String(c.name),
        externalId: c.external_id ? String(c.external_id) : undefined,
        createdAt: String(c.created_at),
      })),
      organizations: orgRows.map((o) => ({
        id: String(o.id),
        name: String(o.name),
        identifier: String(o.identifier),
        plan: o.plan as "free" | "teams" | "enterprise",
        createdAt: String(o.created_at),
      })),
      sends: sends.map((s) => ({
        id: String(s.id),
        accessId: String(s.access_id),
        name: s.name ? String(s.name) : undefined,
        type: s.type as "text" | "file",
        maxAccessCount: s.max_access_count ? Number(s.max_access_count) : undefined,
        accessCount: Number(s.access_count),
        expirationDate: s.expiration_date ? String(s.expiration_date) : undefined,
        passwordProtected: Boolean(s.password_hash),
        disabled: Boolean(s.disabled),
        encryptedPayload: {
          iv: String(s.encrypted_payload_iv),
          data: String(s.encrypted_payload_data),
        },
        createdAt: String(s.created_at),
      })),
      syncTimestamp: nowIso(),
    };

    return reply.send(response);
  });

  app.post<{ Body: CipherBody }>("/ciphers", { preHandler: [app.authenticate] }, async (request, reply) => {
    const userId = getUserId(request);
    const body = request.body;
    const id = uuid();
    const ts = nowIso();

    db.prepare(`
      INSERT INTO ciphers (
        id, user_id, organization_id, type, name, notes, folder_id,
        favorite, reprompt, encrypted_data_iv, encrypted_data_data, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      userId,
      body.organizationId ?? null,
      body.type,
      body.name,
      body.notes ?? null,
      body.folderId ?? null,
      body.favorite ? 1 : 0,
      body.reprompt ? 1 : 0,
      body.encryptedData.iv,
      body.encryptedData.data,
      ts,
      ts,
    );

    if (body.collectionIds?.length) {
      const insert = db.prepare("INSERT INTO cipher_collections (cipher_id, collection_id) VALUES (?, ?)");
      for (const collectionId of body.collectionIds) {
        insert.run(id, collectionId);
      }
    }

    return reply.code(201).send({ id, createdAt: ts, updatedAt: ts });
  });

  app.put<{ Params: { id: string }; Body: CipherBody }>(
    "/ciphers/:id",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { id } = request.params;
      const body = request.body;
      const existing = db.prepare("SELECT id FROM ciphers WHERE id = ? AND user_id = ?").get(id, userId);
      if (!existing) return reply.code(404).send({ code: "not_found", message: "Cipher not found" });

      const ts = nowIso();
      db.prepare(`
        UPDATE ciphers SET
          type = ?, name = ?, notes = ?, folder_id = ?, organization_id = ?,
          favorite = ?, reprompt = ?,
          encrypted_data_iv = ?, encrypted_data_data = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
      `).run(
        body.type,
        body.name,
        body.notes ?? null,
        body.folderId ?? null,
        body.organizationId ?? null,
        body.favorite ? 1 : 0,
        body.reprompt ? 1 : 0,
        body.encryptedData.iv,
        body.encryptedData.data,
        ts,
        id,
        userId,
      );

      db.prepare("DELETE FROM cipher_collections WHERE cipher_id = ?").run(id);
      if (body.collectionIds?.length) {
        const insert = db.prepare("INSERT INTO cipher_collections (cipher_id, collection_id) VALUES (?, ?)");
        for (const collectionId of body.collectionIds) {
          insert.run(id, collectionId);
        }
      }

      return reply.send({ id, updatedAt: ts });
    },
  );

  app.delete<{ Params: { id: string } }>(
    "/ciphers/:id",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { id } = request.params;
      const result = db.prepare("DELETE FROM ciphers WHERE id = ? AND user_id = ?").run(id, userId);
      if (result.changes === 0) {
        return reply.code(404).send({ code: "not_found", message: "Cipher not found" });
      }
      return reply.code(204).send();
    },
  );

  app.post<{ Body: { name: string } }>(
    "/folders",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const id = uuid();
      const ts = nowIso();
      db.prepare(`
        INSERT INTO folders (id, user_id, name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(id, userId, request.body.name, ts, ts);
      return reply.code(201).send(mapFolder({ id, user_id: userId, name: request.body.name, created_at: ts, updated_at: ts }));
    },
  );
}

function mapFolder(row: Record<string, unknown>): Folder {
  return {
    id: String(row.id),
    name: String(row.name),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

function mapCipher(row: Record<string, unknown>): EncryptedCipher {
  return {
    id: String(row.id),
    type: row.type as EncryptedCipher["type"],
    name: String(row.name),
    notes: row.notes ? String(row.notes) : undefined,
    folderId: row.folder_id ? String(row.folder_id) : null,
    organizationId: row.organization_id ? String(row.organization_id) : null,
    favorite: Boolean(row.favorite),
    reprompt: Boolean(row.reprompt),
    encryptedData: {
      iv: String(row.encrypted_data_iv),
      data: String(row.encrypted_data_data),
    },
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}
