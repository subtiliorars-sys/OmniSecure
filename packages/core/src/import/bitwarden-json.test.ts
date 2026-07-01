import test from "node:test";
import assert from "node:assert/strict";
import { parseBitwardenJson } from "./bitwarden-json.js";
import { exportBitwardenCsv } from "../export/bitwarden-csv.js";

test("parseBitwardenJson maps login items", () => {
  const json = JSON.stringify({
    encrypted: false,
    folders: [{ id: "f1", name: "Work" }],
    items: [{
      type: 1,
      name: "GitHub",
      folderId: "f1",
      login: {
        username: "dev",
        password: "secret",
        uris: [{ uri: "https://github.com" }],
      },
    }],
  });

  const rows = parseBitwardenJson(json);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.name, "GitHub");
  assert.equal(rows[0]?.folder, "Work");
  assert.equal(rows[0]?.login?.username, "dev");
});

test("exportBitwardenCsv includes login fields", () => {
  const csv = exportBitwardenCsv([
    {
      id: "1",
      type: "login",
      name: "Example",
      data: { username: "user", password: "pass", uris: ["https://example.com"] },
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    },
  ], []);
  assert.match(csv, /login_username,login_password,login_totp/);
  assert.ok(csv.includes("Example"));
  assert.ok(csv.includes("user,pass,"));
});
