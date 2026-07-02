import type { FastifyInstance } from "fastify";
import { v4 as uuid } from "uuid";
import { generateAccessToken, generateUserKeys } from "@omnisecure/crypto";
import type { AppDatabase } from "../db/schema.js";
import { nowIso } from "../lib/utils.js";
import { getScimOrgId, hashScimToken } from "./sso.js";

function scimAuth(_app: FastifyInstance, db: AppDatabase) {
  return async (request: import("fastify").FastifyRequest, reply: import("fastify").FastifyReply) => {
    const orgId = getScimOrgId(request, db);
    if (!orgId) {
      return reply.code(401).send({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "Invalid SCIM bearer token",
        status: "401",
      });
    }
    request.scimOrgId = orgId;
  };
}

declare module "fastify" {
  interface FastifyRequest {
    scimOrgId?: string;
  }
}

export async function scimRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  const authenticate = scimAuth(app, db);

  app.post<{ Params: { orgId: string } }>(
    "/organizations/:orgId/scim-tokens",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = String((request.user as { sub: string }).sub);
      const { orgId } = request.params;
      const member = db.prepare(`
        SELECT role FROM organization_users WHERE organization_id = ? AND user_id = ?
      `).get(orgId, userId) as { role: string } | undefined;
      if (!member || (member.role !== "owner" && member.role !== "admin")) {
        return reply.code(403).send({ code: "forbidden", message: "Admin role required" });
      }

      const token = generateAccessToken();
      const id = uuid();
      const ts = nowIso();
      db.prepare(`
        INSERT INTO scim_tokens (id, organization_id, token_hash, token_hint, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(id, orgId, hashScimToken(token), token.slice(0, 6), ts);

      return reply.code(201).send({ id, token, tokenHint: token.slice(0, 6), createdAt: ts });
    },
  );

  app.get("/Users", { preHandler: [authenticate] }, async (request, reply) => {
    const orgId = request.scimOrgId!;
    const users = db.prepare(`
      SELECT u.id, u.email, u.name, ou.status
      FROM users u
      JOIN organization_users ou ON ou.user_id = u.id
      WHERE ou.organization_id = ?
    `).all(orgId) as Array<Record<string, unknown>>;

    return reply.send({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: users.length,
      Resources: users.map((user) => scimUserResource(user)),
    });
  });

  app.post<{ Body: { userName?: string; name?: { formatted?: string }; active?: boolean } }>(
    "/Users",
    { preHandler: [authenticate] },
    async (request, reply) => {
      const orgId = request.scimOrgId!;
      const email = request.body.userName?.toLowerCase();
      if (!email) {
        return reply.code(400).send({ detail: "userName required", status: "400" });
      }

      let user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as Record<string, unknown> | undefined;
      if (!user) {
        const id = uuid();
        const ts = nowIso();
        const placeholderPassword = generateAccessToken();
        const { masterPasswordHash, userKeys } = generateUserKeys(placeholderPassword, email);
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
          email,
          request.body.name?.formatted ?? null,
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
        user = db.prepare("SELECT * FROM users WHERE id = ?").get(id) as Record<string, unknown>;
      }

      db.prepare(`
        INSERT INTO organization_users (organization_id, user_id, role, status)
        VALUES (?, ?, 'user', 'confirmed')
        ON CONFLICT(organization_id, user_id) DO UPDATE SET status = 'confirmed'
      `).run(orgId, user!.id);

      return reply.code(201).send(scimUserResource({
        id: user!.id,
        email,
        name: request.body.name?.formatted ?? user!.name,
        status: "confirmed",
      }));
    },
  );

  app.patch<{ Params: { id: string }; Body: { active?: boolean; name?: { formatted?: string } } }>(
    "/Users/:id",
    { preHandler: [authenticate] },
    async (request, reply) => {
      const orgId = request.scimOrgId!;
      const member = db.prepare(`
        SELECT u.id, u.email, u.name, ou.status
        FROM users u
        JOIN organization_users ou ON ou.user_id = u.id
        WHERE ou.organization_id = ? AND u.id = ?
      `).get(orgId, request.params.id) as Record<string, unknown> | undefined;
      if (!member) return reply.code(404).send({ detail: "User not found", status: "404" });

      if (request.body.name?.formatted) {
        db.prepare("UPDATE users SET name = ?, updated_at = ? WHERE id = ?").run(
          request.body.name.formatted,
          nowIso(),
          request.params.id,
        );
      }
      if (request.body.active === false) {
        db.prepare(`
          UPDATE organization_users SET status = 'suspended'
          WHERE organization_id = ? AND user_id = ?
        `).run(orgId, request.params.id);
      } else if (request.body.active === true) {
        db.prepare(`
          UPDATE organization_users SET status = 'confirmed'
          WHERE organization_id = ? AND user_id = ?
        `).run(orgId, request.params.id);
      }

      const updated = db.prepare(`
        SELECT u.id, u.email, u.name, ou.status
        FROM users u
        JOIN organization_users ou ON ou.user_id = u.id
        WHERE ou.organization_id = ? AND u.id = ?
      `).get(orgId, request.params.id) as Record<string, unknown>;

      return reply.send(scimUserResource(updated));
    },
  );

  app.delete<{ Params: { id: string } }>(
    "/Users/:id",
    { preHandler: [authenticate] },
    async (request, reply) => {
      const orgId = request.scimOrgId!;
      db.prepare(`
        DELETE FROM organization_users WHERE organization_id = ? AND user_id = ?
      `).run(orgId, request.params.id);
      return reply.code(204).send();
    },
  );
}

function scimUserResource(user: Record<string, unknown>) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: String(user.id),
    userName: String(user.email),
    name: { formatted: user.name ? String(user.name) : String(user.email) },
    emails: [{ value: String(user.email), primary: true }],
    active: String(user.status ?? "confirmed") === "confirmed",
    meta: { resourceType: "User" },
  };
}
