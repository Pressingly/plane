// `process.env` is replaced at build time in apps/web/vite.config.ts (`define`).
export {};

declare global {
  const process: {
    env: Record<string, string | undefined> & {
      /** Portal hostname prefix for logout; must be set at build time (see vite.config.ts). */
      SMB_NAME: string;
    };
  };
}
