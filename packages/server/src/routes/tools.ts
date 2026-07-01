import type { FastifyInstance } from "fastify";
import {
  generatePassphrase,
  generatePassword,
  generateUsername,
  scorePasswordStrength,
} from "@omnisecure/core";

export async function toolsRoutes(app: FastifyInstance): Promise<void> {
  app.get("/tools/password", async (request, reply) => {
    const query = request.query as Record<string, string | undefined>;
    const length = Number(query.length ?? 20);
    return reply.send({
      password: generatePassword({ length }),
    });
  });

  app.get("/tools/passphrase", async (request, reply) => {
    const query = request.query as Record<string, string | undefined>;
    const words = Number(query.words ?? 6);
    return reply.send({
      passphrase: generatePassphrase(words),
    });
  });

  app.get("/tools/username", async (request, reply) => {
    const query = request.query as Record<string, string | undefined>;
    const length = Number(query.length ?? 12);
    return reply.send({
      username: generateUsername(length),
    });
  });

  app.post<{ Body: { password: string } }>("/tools/password-strength", async (request, reply) => {
    return reply.send(scorePasswordStrength(request.body.password));
  });
}

export async function healthRoutes(app: FastifyInstance): Promise<void> {
  app.get("/health", async (_request, reply) => {
    return reply.send({
      status: "ok",
      service: "omnisecure-api",
      version: "0.3.0",
    });
  });
}
