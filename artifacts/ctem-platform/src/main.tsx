import { createRoot } from "react-dom/client";
import { ClerkProvider } from "@clerk/clerk-react";
import App from "./App";
import "./index.css";

const clerkKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined;
const root = createRoot(document.getElementById("root")!);

if (clerkKey) {
  root.render(
    <ClerkProvider publishableKey={clerkKey}>
      <App />
    </ClerkProvider>
  );
} else {
  root.render(<App />);
}
