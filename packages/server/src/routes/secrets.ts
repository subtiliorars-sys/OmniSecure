import type { FastifyInstance } from "fastify";
import { v4 as uuid } from "uuid";
import { generateAccessToken, hashToken } from "@omnisecure/crypto";
import type { AppDatabase } from "../db/schema.js";
import { getUserId, nowIso } from "../lib/utils.js";

interface CreateProjectBody {
  name: string;
}

interface CreateSecretBody {
  key: string;
  note?: string;
  encryptedValue: { iv: string; data: string };
}

export async function secretsRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.post<{ Params: { orgId: string }; Body: CreateProjectBody }>(
    "/organizations/:orgId/projects",
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
        INSERT INTO secret_projects (id, organization_id, name, created_at)
        VALUES (?, ?, ?, ?)
      `).run(id, orgId, request.body.name, ts);

      return reply.code(201).send({ id, organizationId: orgId, name: request.body.name, createdAt: ts });
    },
  );

  app.get<{ Params: { orgId: string } }>(
    "/organizations/:orgId/projects",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { orgId } = request.params;
      const member = db.prepare(`
        SELECT role FROM organization_users WHERE organization_id = ? AND user_id = ?
      `).get(orgId, userId);
      if (!member) return reply.code(403).send({ code: "forbidden", message: "Not a member" });

      const projects = db.prepare(`
        SELECT * FROM secret_projects WHERE organization_id = ?
      `).all(orgId);
      return reply.send({ projects });
    },
  );

  app.post<{ Params: { projectId: string }; Body: CreateSecretBody }>(
    "/projects/:projectId/secrets",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { projectId } = request.params;
      const project = db.prepare(`
        SELECT sp.* FROM secret_projects sp
        JOIN organization_users ou ON ou.organization_id = sp.organization_id
        WHERE sp.id = ? AND ou.user_id = ?
      `).get(projectId, userId);
      if (!project) return reply.code(404).send({ code: "not_found", message: "Project not found" });

      const id = uuid();
      const ts = nowIso();
      db.prepare(`
        INSERT INTO secrets (id, project_id, key_name, note, encrypted_value_iv, encrypted_value_data, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        projectId,
        request.body.key,
        request.body.note ?? null,
        request.body.encryptedValue.iv,
        request.body.encryptedValue.data,
        ts,
        ts,
      );

      return reply.code(201).send({ id, projectId, key: request.body.key, createdAt: ts, updatedAt: ts });
    },
  );

  app.get<{ Params: { projectId: string } }>(
    "/projects/:projectId/secrets",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { projectId } = request.params;
      const project = db.prepare(`
        SELECT sp.* FROM secret_projects sp
        JOIN organization_users ou ON ou.organization_id = sp.organization_id
        WHERE sp.id = ? AND ou.user_id = ?
      `).get(projectId, userId);
      if (!project) return reply.code(404).send({ code: "not_found", message: "Project not found" });

      const secrets = db.prepare(`
        SELECT id, project_id, key_name, note, encrypted_value_iv, encrypted_value_data, created_at, updated_at
        FROM secrets WHERE project_id = ?
      `).all(projectId);

      return reply.send({
        secrets: (secrets as Array<Record<string, unknown>>).map((s) => ({
          id: s.id,
          projectId: s.project_id,
          key: s.key_name,
          note: s.note,
          encryptedValue: { iv: s.encrypted_value_iv, data: s.encrypted_value_data },
          createdAt: s.created_at,
          updatedAt: s.updated_at,
        })),
      });
    },
  );

  app.post<{ Params: { orgId: string }; Body: { name: string } }>(
    "/organizations/:orgId/service-accounts",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { orgId } = request.params;
      const member = db.prepare(`
        SELECT role FROM organization_users WHERE organization_id = ? AND user_id = ? AND role IN ('owner', 'admin')
      `).get(orgId, userId);
      if (!member) return reply.code(403).send({ code: "forbidden", message: "Admin required" });

      const id = uuid();
      const token = generateAccessToken();
      const hint = token.slice(0, 8);
      const ts = nowIso();

      db.prepare(`
        INSERT INTO service_accounts (id, organization_id, name, token_hash, token_hint, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(id, orgId, request.body.name, hashToken(token), hint, ts);

      return reply.code(201).send({
        id,
        name: request.body.name,
        accessToken: token,
        tokenHint: hint,
        createdAt: ts,
      });
    },
  );
}
