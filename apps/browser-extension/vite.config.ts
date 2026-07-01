import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vite";

const outDir = resolve(__dirname, "dist");

export default defineConfig({
  build: {
    outDir,
    emptyOutDir: true,
    rollupOptions: {
      input: {
        background: resolve(__dirname, "src/background.ts"),
        content: resolve(__dirname, "src/content.ts"),
        popup: resolve(__dirname, "src/popup/popup.ts"),
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name].js",
        assetFileNames: "[name][extname]",
      },
    },
  },
  plugins: [
    {
      name: "omnisecure-extension-assets",
      closeBundle() {
        mkdirSync(resolve(outDir, "icons"), { recursive: true });
        copyFileSync(resolve(__dirname, "manifest.json"), resolve(outDir, "manifest.json"));
        copyFileSync(resolve(__dirname, "src/popup/popup.html"), resolve(outDir, "popup.html"));
        copyFileSync(resolve(__dirname, "src/popup/popup.css"), resolve(outDir, "popup.css"));
        copyFileSync(resolve(__dirname, "src/content/content.css"), resolve(outDir, "content.css"));
        for (const size of [16, 48, 128]) {
          copyFileSync(
            resolve(__dirname, `icons/icon${size}.png`),
            resolve(outDir, `icons/icon${size}.png`),
          );
        }
        const popupHtml = readFileSync(resolve(outDir, "popup.html"), "utf8");
        writeFileSync(
          resolve(outDir, "popup.html"),
          popupHtml.replace('src="./popup.ts"', 'src="./popup.js"'),
        );
      },
    },
  ],
});
