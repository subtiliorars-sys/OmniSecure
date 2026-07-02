import type { FastifyInstance, FastifyRequest } from "fastify";
import { createHash, randomBytes } from "node:crypto";
import { v4 as uuid } from "uuid";
import { generateAccessToken, generateUserKeys, hashToken } from "@omnisecure/crypto";
import type { AppDatabase } from "../db/schema.js";
import { nowIso } from "../lib/utils.js";
import { serverConfig } from "../lib/config.js";

interface OidcConfigBody {
  provider: "oidc" | "saml";
  issuer: string;
  clientId?: string;
  clientSecret?: string;
  metadataUrl?: string;
  samlEntryPoint?: string;
  samlCert?: string;
  enabled?: boolean;
}

function assertOrgAdmin(db: AppDatabase, orgId: string, userId: string): boolean {
  const member = db.prepare(`
    SELECT role FROM organization_users WHERE organization_id = ? AND user_id = ?
  `).get(orgId, userId) as { role: string } | undefined;
  return Boolean(member && (member.role === "owner" || member.role === "admin"));
}

async function fetchOidcMetadata(metadataUrl: string): Promise<Record<string, string>> {
  const response = await fetch(metadataUrl);
  if (!response.ok) throw new Error("Failed to fetch OIDC metadata");
  const metadata = await response.json() as Record<string, string>;
  return metadata;
}

export async function ssoRoutes(app: FastifyInstance, db: AppDatabase): Promise<void> {
  app.put<{ Params: { orgId: string }; Body: OidcConfigBody }>(
    "/organizations/:orgId/idp",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = String((request.user as { sub: string }).sub);
      const { orgId } = request.params;
      if (!assertOrgAdmin(db, orgId, userId)) {
        return reply.code(403).send({ code: "forbidden", message: "Admin role required" });
      }

      const body = request.body;
      const ts = nowIso();
      db.prepare(`
        INSERT INTO organization_idp (
          organization_id, provider, issuer, client_id, client_secret,
          metadata_url, saml_entry_point, saml_cert, enabled, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(organization_id) DO UPDATE SET
          provider = excluded.provider,
          issuer = excluded.issuer,
          client_id = excluded.client_id,
          client_secret = excluded.client_secret,
          metadata_url = excluded.metadata_url,
          saml_entry_point = excluded.saml_entry_point,
          saml_cert = excluded.saml_cert,
          enabled = excluded.enabled
      `).run(
        orgId,
        body.provider,
        body.issuer,
        body.clientId ?? null,
        body.clientSecret ?? null,
        body.metadataUrl ?? null,
        body.samlEntryPoint ?? null,
        body.samlCert ?? null,
        body.enabled ? 1 : 0,
        ts,
      );

      return reply.send({ organizationId: orgId, provider: body.provider, enabled: Boolean(body.enabled) });
    },
  );

  app.get<{ Params: { orgId: string } }>(
    "/organizations/:orgId/idp",
    { preHandler: [app.authenticate] },
    async (request, reply) => {
      const userId = String((request.user as { sub: string }).sub);
      const { orgId } = request.params;
      if (!assertOrgAdmin(db, orgId, userId)) {
        return reply.code(403).send({ code: "forbidden", message: "Admin role required" });
      }

      const idp = db.prepare("SELECT * FROM organization_idp WHERE organization_id = ?").get(orgId);
      return reply.send({ idp });
    },
  );

  app.get<{ Params: { orgId: string } }>("/sso/:orgId/login", async (request, reply) => {
    const { orgId } = request.params;
    const idp = db.prepare(`
      SELECT * FROM organization_idp WHERE organization_id = ? AND enabled = 1
    `).get(orgId) as Record<string, unknown> | undefined;
    if (!idp) return reply.code(404).send({ code: "sso_disabled", message: "SSO not configured" });

    if (String(idp.provider) === "saml") {
      const redirect = `${serverConfig.apiPublicUrl}/api/sso/${orgId}/saml/login`;
      return reply.redirect(redirect);
    }

    const metadata = idp.metadata_url
      ? await fetchOidcMetadata(String(idp.metadata_url))
      : { authorization_endpoint: `${idp.issuer}/authorize` };

    const state = randomBytes(16).toString("hex");
    const nonce = randomBytes(16).toString("hex");
    const redirectUri = `${serverConfig.publicUrl}/sso/callback`;
    db.prepare(`
      INSERT INTO sso_states (id, organization_id, state, nonce, redirect_uri, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(uuid(), orgId, state, nonce, redirectUri, new Date(Date.now() + 10 * 60_000).toISOString(), nowIso());

    const params = new URLSearchParams({
      client_id: String(idp.client_id),
      response_type: "code",
      scope: "openid email profile",
      redirect_uri: redirectUri,
      state,
      nonce,
    });
    const authUrl = `${metadata.authorization_endpoint}?${params.toString()}`;
    return reply.redirect(authUrl);
  });

  app.get<{ Querystring: { code?: string; state?: string } }>("/sso/callback", async (request, reply) => {
    const { code, state } = request.query;
    if (!code || !state) {
      return reply.code(400).send({ code: "invalid_request", message: "Missing code or state" });
    }

    const ssoState = db.prepare(`
      SELECT * FROM sso_states WHERE state = ? AND expires_at > ?
    `).get(state, nowIso()) as Record<string, unknown> | undefined;
    if (!ssoState) {
      return reply.code(400).send({ code: "invalid_state", message: "SSO state expired" });
    }

    const orgId = String(ssoState.organization_id);
    const idp = db.prepare("SELECT * FROM organization_idp WHERE organization_id = ?").get(orgId) as Record<string, unknown>;
    const metadata = idp.metadata_url
      ? await fetchOidcMetadata(String(idp.metadata_url))
      : {
          token_endpoint: `${idp.issuer}/token`,
          userinfo_endpoint: `${idp.issuer}/userinfo`,
        };

    const tokenResponse = await fetch(String(metadata.token_endpoint), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: String(ssoState.redirect_uri),
        client_id: String(idp.client_id),
        client_secret: String(idp.client_secret ?? ""),
      }),
    });
    const tokenJson = await tokenResponse.json() as { access_token?: string; id_token?: string };
    if (!tokenResponse.ok || !tokenJson.access_token) {
      return reply.code(401).send({ code: "token_exchange_failed", message: "OIDC token exchange failed" });
    }

    const profileResponse = await fetch(String(metadata.userinfo_endpoint), {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });
    const profile = await profileResponse.json() as { email?: string; name?: string; sub?: string };
    if (!profile.email) {
      return reply.code(400).send({ code: "missing_email", message: "IdP profile missing email claim" });
    }

    const email = profile.email.toLowerCase();
    let user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as Record<string, unknown> | undefined;
    if (!user) {
      const id = uuid();
      const ts = nowIso();
      const placeholderPassword = randomBytes(32).toString("hex");
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
        profile.name ?? null,
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
      db.prepare(`
        INSERT INTO organization_users (organization_id, user_id, role, status)
        VALUES (?, ?, 'user', 'confirmed')
      `).run(orgId, id);
    }

    const userId = String(user!.id);
    const token = generateAccessToken();
    db.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(uuid(), userId, hashToken(token), new Date(Date.now() + 7 * 86400000).toISOString(), nowIso());

    const jwt = app.jwt.sign({ sub: userId, email }, { expiresIn: "7d" });
    const redirect = `${serverConfig.publicUrl}/?token=${encodeURIComponent(jwt)}&sso=1`;
    db.prepare("DELETE FROM sso_states WHERE id = ?").run(ssoState.id);
    return reply.redirect(redirect);
  });

  app.get<{ Params: { orgId: string } }>("/sso/:orgId/saml/login", async (request, reply) => {
    const { orgId } = request.params;
    const idp = db.prepare(`
      SELECT * FROM organization_idp WHERE organization_id = ? AND provider = 'saml' AND enabled = 1
    `).get(orgId) as Record<string, unknown> | undefined;
    if (!idp?.saml_entry_point) {
      return reply.code(404).send({ code: "saml_not_configured", message: "SAML IdP not configured" });
    }

    const relayState = randomBytes(12).toString("hex");
    db.prepare(`
      INSERT INTO sso_states (id, organization_id, state, nonce, redirect_uri, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      uuid(),
      orgId,
      relayState,
      "",
      `${serverConfig.publicUrl}/sso/saml/callback`,
      new Date(Date.now() + 10 * 60_000).toISOString(),
      nowIso(),
    );

    const params = new URLSearchParams({
      SAMLRequest: Buffer.from(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${uuid()}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${String(idp.saml_entry_point)}" AssertionConsumerServiceURL="${serverConfig.apiPublicUrl}/api/sso/${orgId}/saml/acs"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${serverConfig.webauthn.rpName}</saml:Issuer></samlp:AuthnRequest>`).toString("base64"),
      RelayState: relayState,
    });
    return reply.redirect(`${String(idp.saml_entry_point)}?${params.toString()}`);
  });

  app.post<{ Params: { orgId: string }; Body: { SAMLResponse?: string; RelayState?: string } }>(
    "/sso/:orgId/saml/acs",
    async (request, reply) => {
      const { orgId } = request.params;
      const relayState = request.body.RelayState ?? "";
      const ssoState = db.prepare(`
        SELECT * FROM sso_states WHERE state = ? AND organization_id = ? AND expires_at > ?
      `).get(relayState, orgId, nowIso()) as Record<string, unknown> | undefined;
      if (!ssoState) {
        return reply.code(400).send({ code: "invalid_relay_state", message: "SAML relay state expired" });
      }

      const decoded = Buffer.from(String(request.body.SAMLResponse ?? ""), "base64").toString("utf8");
      const emailMatch = decoded.match(/NameID[^>]*>([^<]+)</i) ?? decoded.match(/email[^>]*>([^<]+)</i);
      const email = emailMatch?.[1]?.toLowerCase();
      if (!email) {
        return reply.code(400).send({ code: "saml_parse_failed", message: "Could not parse SAML assertion email" });
      }

      let user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as Record<string, unknown> | undefined;
      if (!user) {
        const id = uuid();
        const ts = nowIso();
        const placeholderPassword = randomBytes(32).toString("hex");
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
          null,
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
        db.prepare(`
          INSERT INTO organization_users (organization_id, user_id, role, status)
          VALUES (?, ?, 'user', 'confirmed')
        `).run(orgId, id);
      }

      const userId = String(user!.id);
      const jwt = app.jwt.sign({ sub: userId, email }, { expiresIn: "7d" });
      db.prepare("DELETE FROM sso_states WHERE id = ?").run(ssoState.id);
      return reply.redirect(`${serverConfig.publicUrl}/?token=${encodeURIComponent(jwt)}&sso=saml`);
    },
  );
}

export function hashScimToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function getScimOrgId(request: FastifyRequest, db: AppDatabase): string | null {
  const auth = request.headers.authorization ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return null;
  const row = db.prepare(`
    SELECT organization_id FROM scim_tokens WHERE token_hash = ?
  `).get(hashScimToken(token)) as { organization_id: string } | undefined;
  return row?.organization_id ?? null;
}
