import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { SendReceivePage } from "./SendReceive";
import "./styles.css";

const sendMatch = window.location.pathname.match(/^\/send\/([^/]+)\/?$/);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {sendMatch ? <SendReceivePage accessId={sendMatch[1]!} /> : <App />}
  </StrictMode>,
);
