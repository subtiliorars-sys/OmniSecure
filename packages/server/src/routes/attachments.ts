import type { FastifyInstance } from "fastify";
import { v4 as uuid } from "uuid";
import type { AppDatabase } from "../db/schema.js";
import { getUserId, nowIso } from "../lib/utils.js";
import { serverConfig } from "../lib/config.js";

interface AttachmentBody {
  fileName: string;
  size: number;
  encryptedData: { iv: string; data: string };
}

export async function attachmentRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.get<{ Params: { cipherId: string } }>(
    "/ciphers/:cipherId/attachments",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const cipher = db.prepare("SELECT id FROM ciphers WHERE id = ? AND user_id = ?").get(
        request.params.cipherId,
        userId,
      );
      if (!cipher) return reply.code(404).send({ code: "not_found", message: "Cipher not found" });

      const attachments = db.prepare(`
        SELECT id, cipher_id, file_name, size, encrypted_data_iv, encrypted_data_data, created_at
        FROM attachments WHERE cipher_id = ? AND user_id = ?
      `).all(request.params.cipherId, userId) as Array<Record<string, unknown>>;

      return reply.send({
        attachments: attachments.map((row) => ({
          id: row.id,
          cipherId: row.cipher_id,
          fileName: row.file_name,
          size: row.size,
          encryptedData: { iv: row.encrypted_data_iv, data: row.encrypted_data_data },
          createdAt: row.created_at,
        })),
      });
    },
  );

  app.post<{ Params: { cipherId: string }; Body: AttachmentBody }>(
    "/ciphers/:cipherId/attachments",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { cipherId } = request.params;
      const body = request.body;

      const cipher = db.prepare("SELECT id FROM ciphers WHERE id = ? AND user_id = ?").get(cipherId, userId);
      if (!cipher) return reply.code(404).send({ code: "not_found", message: "Cipher not found" });

      if (!body.fileName || !body.encryptedData?.iv || !body.encryptedData?.data) {
        return reply.code(400).send({ code: "invalid_request", message: "fileName and encryptedData required" });
      }

      const size = Number(body.size ?? 0);
      if (size <= 0 || size > serverConfig.attachmentMaxBytes) {
        return reply.code(400).send({
          code: "file_too_large",
          message: `Attachment exceeds ${serverConfig.attachmentMaxBytes} byte limit`,
        });
      }

      const id = uuid();
      const ts = nowIso();
      db.prepare(`
        INSERT INTO attachments (
          id, cipher_id, user_id, file_name, size,
          encrypted_data_iv, encrypted_data_data, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        cipherId,
        userId,
        body.fileName,
        size,
        body.encryptedData.iv,
        body.encryptedData.data,
        ts,
      );

      return reply.code(201).send({
        id,
        cipherId,
        fileName: body.fileName,
        size,
        encryptedData: body.encryptedData,
        createdAt: ts,
      });
    },
  );

  app.delete<{ Params: { cipherId: string; attachmentId: string } }>(
    "/ciphers/:cipherId/attachments/:attachmentId",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const result = db.prepare(`
        DELETE FROM attachments WHERE id = ? AND cipher_id = ? AND user_id = ?
      `).run(request.params.attachmentId, request.params.cipherId, userId);
      if (result.changes === 0) {
        return reply.code(404).send({ code: "not_found", message: "Attachment not found" });
      }
      return reply.code(204).send();
    },
  );
}
