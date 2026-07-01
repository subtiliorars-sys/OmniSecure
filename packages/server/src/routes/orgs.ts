import type { FastifyInstance } from "fastify";
import { v4 as uuid } from "uuid";
import { hashMasterPassword } from "@omnisecure/crypto";
import type { AppDatabase } from "../db/schema.js";
import { getUserId, nowIso } from "../lib/utils.js";

interface CreateOrgBody {
  name: string;
  identifier: string;
  plan?: "free" | "teams" | "enterprise";
}

interface CreateSendBody {
  name?: string;
  type: "text" | "file";
  maxAccessCount?: number;
  expirationDate?: string;
  password?: string;
  encryptedPayload: { iv: string; data: string };
}

export async function orgRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.post<{ Body: CreateOrgBody }>(
    "/organizations",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { name, identifier, plan = "free" } = request.body;
      const existing = db.prepare("SELECT id FROM organizations WHERE identifier = ?").get(identifier);
      if (existing) {
        return reply.code(409).send({ code: "identifier_taken", message: "Organization identifier already exists" });
      }

      const id = uuid();
      const ts = nowIso();
      db.prepare(`
        INSERT INTO organizations (id, name, identifier, plan, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(id, name, identifier, plan, ts);
      db.prepare(`
        INSERT INTO organization_users (organization_id, user_id, role, status)
        VALUES (?, ?, 'owner', 'confirmed')
      `).run(id, userId);

      db.prepare(`
        INSERT INTO audit_events (id, organization_id, user_id, event_type, metadata, created_at)
        VALUES (?, ?, ?, 'organization_created', ?, ?)
      `).run(uuid(), id, userId, JSON.stringify({ name }), ts);

      return reply.code(201).send({ id, name, identifier, plan, createdAt: ts });
    },
  );

  app.post<{ Params: { orgId: string }; Body: { name: string } }>(
    "/organizations/:orgId/collections",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { orgId } = request.params;
      const member = db.prepare(`
        SELECT role FROM organization_users WHERE organization_id = ? AND user_id = ?
      `).get(orgId, userId);
      if (!member) return reply.code(403).send({ code: "forbidden", message: "Not a member" });

      const id = uuid();
      const ts = nowIso();
      db.prepare(`
        INSERT INTO collections (id, organization_id, name, created_at)
        VALUES (?, ?, ?, ?)
      `).run(id, orgId, request.body.name, ts);

      return reply.code(201).send({ id, organizationId: orgId, name: request.body.name, createdAt: ts });
    },
  );

  app.get<{ Params: { orgId: string } }>(
    "/organizations/:orgId/events",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { orgId } = request.params;
      const member = db.prepare(`
        SELECT role FROM organization_users WHERE organization_id = ? AND user_id = ?
      `).get(orgId, userId);
      if (!member) return reply.code(403).send({ code: "forbidden", message: "Not a member" });

      const events = db.prepare(`
        SELECT * FROM audit_events WHERE organization_id = ? ORDER BY created_at DESC LIMIT 200
      `).all(orgId);
      return reply.send({ events });
    },
  );
}

export async function sendRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.post<{ Body: CreateSendBody }>(
    "/send",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const body = request.body;
      const id = uuid();
      const accessId = uuid().replace(/-/g, "").slice(0, 18);
      const ts = nowIso();
      const passwordHash = body.password
        ? hashMasterPassword(body.password, accessId)
        : null;

      db.prepare(`
        INSERT INTO sends (
          id, user_id, access_id, name, type, max_access_count, expiration_date,
          password_hash, encrypted_payload_iv, encrypted_payload_data, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        userId,
        accessId,
        body.name ?? null,
        body.type,
        body.maxAccessCount ?? null,
        body.expirationDate ?? null,
        passwordHash,
        body.encryptedPayload.iv,
        body.encryptedPayload.data,
        ts,
      );

      return reply.code(201).send({
        id,
        accessId,
        url: `/send/${accessId}`,
        createdAt: ts,
      });
    },
  );

  app.get<{ Params: { accessId: string } }>(
    "/send/:accessId",
    async (request, reply) => {
      const { accessId } = request.params;
      const send = db.prepare("SELECT * FROM sends WHERE access_id = ? AND disabled = 0").get(accessId) as Record<string, unknown> | undefined;
      if (!send) return reply.code(404).send({ code: "not_found", message: "Send not found" });

      if (send.expiration_date && new Date(String(send.expiration_date)) < new Date()) {
        return reply.code(410).send({ code: "expired", message: "Send has expired" });
      }
      if (send.max_access_count && Number(send.access_count) >= Number(send.max_access_count)) {
        return reply.code(410).send({ code: "max_access", message: "Maximum access count reached" });
      }

      db.prepare("UPDATE sends SET access_count = access_count + 1 WHERE id = ?").run(send.id);

      return reply.send({
        id: send.id,
        accessId: send.access_id,
        name: send.name,
        type: send.type,
        passwordProtected: Boolean(send.password_hash),
        encryptedPayload: {
          iv: send.encrypted_payload_iv,
          data: send.encrypted_payload_data,
        },
      });
    },
  );
}

export async function emergencyRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.post<{ Body: { granteeEmail: string; waitDays?: number } }>(
    "/emergency-access",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const id = uuid();
      const ts = nowIso();
      db.prepare(`
        INSERT INTO emergency_access (id, grantor_user_id, grantee_email, wait_days, status, created_at)
        VALUES (?, ?, ?, ?, 'pending', ?)
      `).run(id, userId, request.body.granteeEmail.toLowerCase(), request.body.waitDays ?? 7, ts);
      return reply.code(201).send({ id, status: "pending", waitDays: request.body.waitDays ?? 7 });
    },
  );

  app.get("/emergency-access", { preHandler: [app.authenticate] }, async (request, reply) => {
    const userId = getUserId(request);
    const grants = db.prepare(`
      SELECT * FROM emergency_access WHERE grantor_user_id = ?
    `).all(userId);
    return reply.send({ grants });
  });
}
