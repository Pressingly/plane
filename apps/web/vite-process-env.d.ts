// `process.env` is replaced at build time in apps/web/vite.config.ts (`define`).
export {};

declare global {
  const process: {
    env: Record<string, string | undefined>;
  };
}
