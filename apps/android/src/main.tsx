import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {/* Last resort only. The boundaries that can actually recover — one per tab,
        with reset keys — are mounted by `App`, above `main` and below this one:
        a single root boundary with no props is the reason that machinery used to
        be unreachable, and a crash in it has nowhere left to fall back to. */}
    <ErrorBoundary label="Aether">
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
);
