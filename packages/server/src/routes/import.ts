import type { FastifyInstance } from "fastify";
import { v4 as uuid } from "uuid";
import type { AppDatabase } from "../db/schema.js";
import { getUserId, nowIso } from "../lib/utils.js";

interface ImportCipher {
  type: string;
  name: string;
  notes?: string;
  folderName?: string;
  favorite?: boolean;
  reprompt?: boolean;
  encryptedData: { iv: string; data: string };
}

interface ImportBody {
  folders?: string[];
  ciphers: ImportCipher[];
}

export async function importRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.post<{ Body: ImportBody }>(
    "/import",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = getUserId(request);
      const { ciphers, folders = [] } = request.body;

      if (!Array.isArray(ciphers) || ciphers.length === 0) {
        return reply.code(400).send({ code: "invalid_request", message: "No ciphers to import" });
      }

      const folderMap = new Map<string, string>();
      const existingFolders = db.prepare("SELECT id, name FROM folders WHERE user_id = ?").all(userId) as Array<{ id: string; name: string }>;
      for (const f of existingFolders) folderMap.set(f.name.toLowerCase(), f.id);

      const folderNames = new Set<string>();
      for (const name of folders) {
        if (name.trim()) folderNames.add(name.trim());
      }
      for (const cipher of ciphers) {
        if (cipher.folderName?.trim()) folderNames.add(cipher.folderName.trim());
      }

      const ts = nowIso();
      const insertFolder = db.prepare(`
        INSERT INTO folders (id, user_id, name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
      `);

      for (const name of folderNames) {
        const key = name.toLowerCase();
        if (folderMap.has(key)) continue;
        const id = uuid();
        insertFolder.run(id, userId, name, ts, ts);
        folderMap.set(key, id);
      }

      const insertCipher = db.prepare(`
        INSERT INTO ciphers (
          id, user_id, organization_id, type, name, notes, folder_id,
          favorite, reprompt, encrypted_data_iv, encrypted_data_data, created_at, updated_at
        ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      let imported = 0;
      for (const cipher of ciphers) {
        const folderId = cipher.folderName
          ? folderMap.get(cipher.folderName.toLowerCase()) ?? null
          : null;
        insertCipher.run(
          uuid(),
          userId,
          cipher.type,
          cipher.name,
          cipher.notes ?? null,
          folderId,
          cipher.favorite ? 1 : 0,
          cipher.reprompt ? 1 : 0,
          cipher.encryptedData.iv,
          cipher.encryptedData.data,
          ts,
          ts,
        );
        imported++;
      }

      return reply.send({ imported, foldersCreated: folderNames.size, importedAt: ts });
    },
  );
}
