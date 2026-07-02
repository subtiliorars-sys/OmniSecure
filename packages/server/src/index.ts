#!/usr/bin/env node
import Fastify from "fastify";
import cors from "@fastify/cors";
import jwt from "@fastify/jwt";
import { createDatabase } from "./db/schema.js";
import { serverConfig } from "./lib/config.js";
import { authRoutes } from "./routes/auth.js";
import { vaultRoutes } from "./routes/vault.js";
import { orgRoutes, sendRoutes, emergencyRoutes } from "./routes/orgs.js";
import { secretsRoutes } from "./routes/secrets.js";
import { toolsRoutes, healthRoutes } from "./routes/tools.js";
import { importRoutes } from "./routes/import.js";
import { attachmentRoutes } from "./routes/attachments.js";
import { webauthnRoutes } from "./routes/webauthn.js";
import { ssoRoutes } from "./routes/sso.js";
import { scimRoutes } from "./routes/scim.js";

async function main(): Promise<void> {
  const db = createDatabase(serverConfig.dbPath);
  const app = Fastify({ logger: true });

  await app.register(cors, { origin: true });
  await app.register(jwt, { secret: serverConfig.jwtSecret });

  app.decorate("authenticate", async (request, reply) => {
    try {
      await request.jwtVerify();
    } catch {
      reply.code(401).send({ code: "unauthorized", message: "Authentication required" });
    }
  });

  await app.register(healthRoutes);
  await app.register(toolsRoutes);
  await app.register(async (instance) => authRoutes(instance, db), { prefix: "/api/auth" });
  await app.register(async (instance) => webauthnRoutes(instance, db), { prefix: "/api/webauthn" });
  await app.register(async (instance) => {
    await vaultRoutes(instance, db);
    await importRoutes(instance, db);
    await attachmentRoutes(instance, db);
  }, { prefix: "/api/vault" });
  await app.register(async (instance) => {
    await orgRoutes(instance, db);
    await sendRoutes(instance, db);
    await emergencyRoutes(instance, db);
    await ssoRoutes(instance, db);
  }, { prefix: "/api" });
  await app.register(async (instance) => secretsRoutes(instance, db), { prefix: "/api/secrets" });
  await app.register(async (instance) => scimRoutes(instance, db), { prefix: "/scim/v2" });

  await app.listen({ port: serverConfig.port, host: serverConfig.host });
  app.log.info(`OmniSecure API listening on http://${serverConfig.host}:${serverConfig.port}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

declare module "fastify" {
  interface FastifyInstance {
    authenticate: (request: import("fastify").FastifyRequest, reply: import("fastify").FastifyReply) => Promise<void>;
  }
}
