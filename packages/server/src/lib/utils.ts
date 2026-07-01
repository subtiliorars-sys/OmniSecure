import type { FastifyRequest } from "fastify";

export interface JwtUser {
  sub: string;
  email: string;
}

export function getUserId(request: FastifyRequest): string {
  const user = request.user as JwtUser;
  return user.sub;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function parseJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}
