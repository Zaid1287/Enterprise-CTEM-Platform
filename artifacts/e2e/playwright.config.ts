import { defineConfig, devices } from "@playwright/test";
import { execSync } from "child_process";

/**
 * Resolve the Nix-managed Chromium binary at runtime.
 * On NixOS (Replit), Playwright's bundled headless shell lacks system libs (libglib etc).
 * Using the Nix-packaged Chromium (declared in replit.nix) avoids that entirely.
 */
const chromiumExecutablePath = (() => {
  try {
    return execSync("which chromium", { encoding: "utf8" }).trim();
  } catch {
    return undefined;
  }
})();

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://localhost:80",
    trace: "on-first-retry",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    launchOptions: {
      executablePath: chromiumExecutablePath,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    },
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
