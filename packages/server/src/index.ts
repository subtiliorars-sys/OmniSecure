#!/usr/bin/env node
import Fastify from "fastify";
import cors from "@fastify/cors";
import jwt from "@fastify/jwt";
import { createDatabase } from "./db/schema.js";
import { authRoutes } from "./routes/auth.js";
import { vaultRoutes } from "./routes/vault.js";
import { orgRoutes, sendRoutes, emergencyRoutes } from "./routes/orgs.js";
import { secretsRoutes } from "./routes/secrets.js";
import { toolsRoutes, healthRoutes } from "./routes/tools.js";
import { importRoutes } from "./routes/import.js";

const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? "0.0.0.0";
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-only-change-in-production";
const DB_PATH = process.env.OMNISECURE_DB ?? "./data/omnisecure.db";

async function main(): Promise<void> {
  const db = createDatabase(DB_PATH);
  const app = Fastify({ logger: true });

  await app.register(cors, { origin: true });
  await app.register(jwt, { secret: JWT_SECRET });

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
  await app.register(async (instance) => {
    await vaultRoutes(instance, db);
    await importRoutes(instance, db);
  }, { prefix: "/api/vault" });
  await app.register(async (instance) => {
    await orgRoutes(instance, db);
    await sendRoutes(instance, db);
    await emergencyRoutes(instance, db);
  }, { prefix: "/api" });
  await app.register(async (instance) => secretsRoutes(instance, db), { prefix: "/api/secrets" });

  await app.listen({ port: PORT, host: HOST });
  app.log.info(`OmniSecure API listening on http://${HOST}:${PORT}`);
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
