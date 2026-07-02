import { useEffect, useState } from "react";
import { ActivityIndicator, Button, FlatList, SafeAreaView, StyleSheet, Text, TextInput, View } from "react-native";
import { StatusBar } from "expo-status-bar";
import type { CipherData } from "@omnisecure/core";
import { decryptJsonBrowser, unlockSymmetricKeyBrowser } from "@omnisecure/crypto/browser";
import { api, clearSession, loadSession, saveSession, type Session } from "./src/api";

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [symmetricKey, setSymmetricKey] = useState<Uint8Array | null>(null);

  useEffect(() => {
    void loadSession().then((value) => {
      setSession(value);
      setLoading(false);
    });
  }, []);

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" />
      </View>
    );
  }

  if (!session) {
    return (
      <LoginScreen
        onLogin={(next) => {
          void saveSession(next).then(() => setSession(next));
        }}
      />
    );
  }

  if (!symmetricKey) {
    return (
      <UnlockScreen
        session={session}
        onUnlock={(key) => setSymmetricKey(key)}
        onLogout={() => {
          void clearSession().then(() => {
            setSession(null);
            setSymmetricKey(null);
          });
        }}
      />
    );
  }

  return (
    <VaultScreen
      session={session}
      symmetricKey={symmetricKey}
      onLogout={() => {
        void clearSession().then(() => {
          setSession(null);
          setSymmetricKey(null);
        });
      }}
    />
  );
}

function LoginScreen({ onLogin }: { onLogin: (session: Session) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError("");
    try {
      const data = await api<{
        token: string;
        user: { email: string };
        userKeys: Session["userKeys"];
      }>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, masterPassword: password }),
      });
      onLogin({ token: data.token, email: data.user.email, userKeys: data.userKeys });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <StatusBar style="light" />
      <Text style={styles.title}>OmniSecure</Text>
      <Text style={styles.subtitle}>OmniTender mobile vault</Text>
      <TextInput style={styles.input} autoCapitalize="none" keyboardType="email-address" placeholder="Email" value={email} onChangeText={setEmail} />
      <TextInput style={styles.input} secureTextEntry placeholder="Master password" value={password} onChangeText={setPassword} />
      {error ? <Text style={styles.error}>{error}</Text> : null}
      <Button title={busy ? "Signing in…" : "Sign in"} onPress={() => void submit()} disabled={busy} />
    </SafeAreaView>
  );
}

function UnlockScreen({
  session,
  onUnlock,
  onLogout,
}: {
  session: Session;
  onUnlock: (key: Uint8Array) => void;
  onLogout: () => void;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    try {
      const key = await unlockSymmetricKeyBrowser(password, session.email, session.userKeys);
      onUnlock(key);
    } catch {
      setError("Invalid master password");
    }
  }

  return (
    <SafeAreaView style={styles.screen}>
      <StatusBar style="light" />
      <Text style={styles.title}>Unlock vault</Text>
      <Text style={styles.subtitle}>{session.email}</Text>
      <TextInput style={styles.input} secureTextEntry placeholder="Master password" value={password} onChangeText={setPassword} />
      {error ? <Text style={styles.error}>{error}</Text> : null}
      <Button title="Unlock" onPress={() => void submit()} />
      <Button title="Use a different account" onPress={onLogout} />
    </SafeAreaView>
  );
}

function VaultScreen({
  session,
  symmetricKey,
  onLogout,
}: {
  session: Session;
  symmetricKey: Uint8Array;
  onLogout: () => void;
}) {
  const [items, setItems] = useState<Array<{ id: string; name: string; type: string; subtitle?: string }>>([]);

  useEffect(() => {
    void api<{ ciphers: Array<{ id: string; name: string; type: string; encryptedData: { iv: string; data: string } }> }>(
      "/api/vault/sync",
      {},
      session.token,
    )
      .then(async (data) => {
        const decrypted = await Promise.all(
          data.ciphers.map(async (cipher) => {
            try {
              const payload = await decryptJsonBrowser<CipherData>(symmetricKey, cipher.encryptedData);
              const username = "username" in payload ? String(payload.username ?? "") : "";
              return {
                id: cipher.id,
                name: cipher.name,
                type: cipher.type,
                subtitle: username || undefined,
              };
            } catch {
              return { id: cipher.id, name: cipher.name, type: cipher.type };
            }
          }),
        );
        setItems(decrypted);
      })
      .catch(() => setItems([]));
  }, [session.token, symmetricKey]);

  return (
    <SafeAreaView style={styles.screen}>
      <StatusBar style="light" />
      <Text style={styles.title}>My vault</Text>
      <Text style={styles.subtitle}>{session.email}</Text>
      <FlatList
        data={items}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <View style={styles.card}>
            <Text style={styles.itemName}>{item.name}</Text>
            <Text style={styles.itemType}>{item.type}{item.subtitle ? ` · ${item.subtitle}` : ""}</Text>
          </View>
        )}
        ListEmptyComponent={<Text style={styles.subtitle}>No items synced yet.</Text>}
      />
      <Button title="Lock & sign out" onPress={onLogout} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  center: { flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: "#0b1220" },
  screen: { flex: 1, backgroundColor: "#0b1220", padding: 20, gap: 12 },
  title: { color: "#f8fafc", fontSize: 28, fontWeight: "700" },
  subtitle: { color: "#94a3b8", marginBottom: 8 },
  input: { backgroundColor: "#111827", color: "#f8fafc", borderRadius: 10, padding: 12 },
  error: { color: "#f87171" },
  card: { backgroundColor: "#111827", borderRadius: 12, padding: 14, marginBottom: 8 },
  itemName: { color: "#f8fafc", fontSize: 16, fontWeight: "600" },
  itemType: { color: "#64748b", marginTop: 4 },
});
