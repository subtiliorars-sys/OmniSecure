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
  accessId?: string;
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

  app.get<{ Params: { orgId: string }; Querystring: { format?: string } }>(
    "/organizations/:orgId/events/export",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { orgId } = request.params;
      const member = db.prepare(`
        SELECT role FROM organization_users WHERE organization_id = ? AND user_id = ?
      `).get(orgId, userId);
      if (!member) return reply.code(403).send({ code: "forbidden", message: "Not a member" });

      const format = (request.query.format ?? "ndjson").toLowerCase();
      const events = db.prepare(`
        SELECT id, organization_id, user_id, event_type, metadata, created_at
        FROM audit_events WHERE organization_id = ? ORDER BY created_at ASC
      `).all(orgId) as Array<Record<string, unknown>>;

      if (format === "csv") {
        const header = "id,organization_id,user_id,event_type,metadata,created_at\n";
        const rows = events.map((event) =>
          [
            event.id,
            event.organization_id,
            event.user_id,
            event.event_type,
            JSON.stringify(event.metadata ?? null),
            event.created_at,
          ].map(csvEscape).join(","),
        );
        reply.header("Content-Type", "text/csv; charset=utf-8");
        reply.header("Content-Disposition", `attachment; filename="omnisecure-audit-${orgId}.csv"`);
        return reply.send(header + rows.join("\n"));
      }

      reply.header("Content-Type", "application/x-ndjson; charset=utf-8");
      reply.header("Content-Disposition", `attachment; filename="omnisecure-audit-${orgId}.ndjson"`);
      return reply.send(events.map((event) => JSON.stringify({
        id: event.id,
        organizationId: event.organization_id,
        userId: event.user_id,
        eventType: event.event_type,
        metadata: event.metadata ? JSON.parse(String(event.metadata)) : null,
        createdAt: event.created_at,
      })).join("\n"));
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
      const accessId = (body.accessId ?? uuid().replace(/-/g, "").slice(0, 18)).toLowerCase();
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

      if (!send.password_hash) {
        db.prepare("UPDATE sends SET access_count = access_count + 1 WHERE id = ?").run(send.id);
      }

      return reply.send({
        id: send.id,
        accessId: send.access_id,
        name: send.name,
        type: send.type,
        passwordProtected: Boolean(send.password_hash),
        encryptedPayload: send.password_hash
          ? null
          : {
              iv: send.encrypted_payload_iv,
              data: send.encrypted_payload_data,
            },
      });
    },
  );

  app.post<{ Params: { accessId: string }; Body: { password: string } }>(
    "/send/:accessId/unlock",
    async (request, reply) => {
      const { accessId } = request.params;
      const send = db.prepare("SELECT * FROM sends WHERE access_id = ? AND disabled = 0").get(accessId) as Record<string, unknown> | undefined;
      if (!send) return reply.code(404).send({ code: "not_found", message: "Send not found" });
      if (!send.password_hash) {
        return reply.code(400).send({ code: "not_password_protected", message: "Send is not password protected" });
      }

      const passwordHash = hashMasterPassword(request.body.password, accessId);
      if (passwordHash !== String(send.password_hash)) {
        return reply.code(403).send({ code: "invalid_password", message: "Incorrect Send password" });
      }

      if (send.expiration_date && new Date(String(send.expiration_date)) < new Date()) {
        return reply.code(410).send({ code: "expired", message: "Send has expired" });
      }
      if (send.max_access_count && Number(send.access_count) >= Number(send.max_access_count)) {
        return reply.code(410).send({ code: "max_access", message: "Maximum access count reached" });
      }

      db.prepare("UPDATE sends SET access_count = access_count + 1 WHERE id = ?").run(send.id);

      return reply.send({
        accessId: send.access_id,
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

  app.get("/emergency-access/incoming", { preHandler: [app.authenticate] }, async (request, reply) => {
    const userId = getUserId(request);
    const user = db.prepare("SELECT email FROM users WHERE id = ?").get(userId) as { email: string } | undefined;
    if (!user) return reply.code(404).send({ code: "not_found", message: "User not found" });

    const grants = db.prepare(`
      SELECT ea.*, u.email AS grantor_email
      FROM emergency_access ea
      JOIN users u ON u.id = ea.grantor_user_id
      WHERE ea.grantee_email = ?
    `).all(user.email.toLowerCase());
    return reply.send({ grants });
  });

  app.post<{ Params: { id: string } }>(
    "/emergency-access/:id/accept",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const user = db.prepare("SELECT email FROM users WHERE id = ?").get(userId) as { email: string } | undefined;
      if (!user) return reply.code(404).send({ code: "not_found", message: "User not found" });

      const grant = db.prepare("SELECT * FROM emergency_access WHERE id = ?").get(request.params.id) as Record<string, unknown> | undefined;
      if (!grant) return reply.code(404).send({ code: "not_found", message: "Grant not found" });
      if (String(grant.grantee_email).toLowerCase() !== user.email.toLowerCase()) {
        return reply.code(403).send({ code: "forbidden", message: "Not the designated grantee" });
      }

      db.prepare("UPDATE emergency_access SET status = 'accepted' WHERE id = ?").run(request.params.id);
      return reply.send({ id: request.params.id, status: "accepted" });
    },
  );

  app.post<{ Params: { id: string } }>(
    "/emergency-access/:id/initiate",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const user = db.prepare("SELECT email FROM users WHERE id = ?").get(userId) as { email: string } | undefined;
      if (!user) return reply.code(404).send({ code: "not_found", message: "User not found" });

      const grant = db.prepare("SELECT * FROM emergency_access WHERE id = ?").get(request.params.id) as Record<string, unknown> | undefined;
      if (!grant) return reply.code(404).send({ code: "not_found", message: "Grant not found" });
      if (String(grant.grantee_email).toLowerCase() !== user.email.toLowerCase()) {
        return reply.code(403).send({ code: "forbidden", message: "Not the designated grantee" });
      }
      if (grant.status !== "accepted") {
        return reply.code(409).send({ code: "not_accepted", message: "Emergency access must be accepted first" });
      }

      const createdAt = new Date(String(grant.created_at));
      const waitMs = Number(grant.wait_days) * 24 * 60 * 60 * 1000;
      if (Date.now() < createdAt.getTime() + waitMs) {
        return reply.code(409).send({ code: "wait_period", message: "Waiting period has not elapsed" });
      }

      db.prepare("UPDATE emergency_access SET status = 'recovery_initiated' WHERE id = ?").run(request.params.id);
      return reply.send({ id: request.params.id, status: "recovery_initiated" });
    },
  );
}

function csvEscape(value: unknown): string {
  const text = String(value ?? "");
  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}
