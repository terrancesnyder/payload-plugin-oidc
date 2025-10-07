import type { Config } from 'payload';
import type { InlineConfig as ViteConfig } from 'vite';

/**
 * Extend Payload's Vite configuration.
 * Mirrors the old extendWebpackConfig behaviour for v3.
 */
export const extendViteConfig =
  (config: Config): ((viteConfig: ViteConfig) => ViteConfig) =>
  (viteConfig) => {
    // 👇 Cast admin to any because Payload's public types don’t yet expose `vite`
    const adminConfig = config.admin as any;

    const existingViteConfig =
      typeof adminConfig?.vite === 'function'
        ? adminConfig.vite(viteConfig)
        : viteConfig;

    return {
      ...existingViteConfig,
      resolve: {
        ...(existingViteConfig.resolve || {}),
        alias: {
          ...(existingViteConfig.resolve?.alias || {}),
          // disable / stub out Node-only modules for the browser admin bundle
          'express-session': false,
          'passport-oauth2': false,
          memorystore: false,
          jsonwebtoken: false,
          passport: false,
        },
      },
    };
  };
