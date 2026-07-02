export const serverConfig = {
  port: Number(process.env.PORT ?? 8787),
  host: process.env.HOST ?? "0.0.0.0",
  jwtSecret: process.env.JWT_SECRET ?? "dev-only-change-in-production",
  dbPath: process.env.OMNISECURE_DB ?? "./data/omnisecure.db",
  publicUrl: process.env.OMNISECURE_PUBLIC_URL ?? "http://localhost:5173",
  apiPublicUrl: process.env.OMNISECURE_API_URL ?? "http://localhost:8787",
  webauthn: {
    rpName: process.env.WEBAUTHN_RP_NAME ?? "OmniSecure",
    rpId: process.env.WEBAUTHN_RP_ID ?? "localhost",
    origin: process.env.WEBAUTHN_ORIGIN ?? "http://localhost:5173",
  },
  attachmentMaxBytes: Number(process.env.ATTACHMENT_MAX_BYTES ?? 5 * 1024 * 1024),
};
