import payload from 'payload';
import type { Config } from 'payload';
import SignInButton from './components/SignInButton/SignInButton';
import { loginHandler } from './lib/login';
import type { oidcPluginOptions } from './types';
import { verify } from './lib/oauth/verify';
import { getCallbackPath } from './lib/helpers';
import { extendViteConfig } from './lib/webpack';

export const oidcPlugin =
  (opts: oidcPluginOptions) =>
  (incomingConfig: Config): Config => {
    console.log('[payload-plugin-oidc] OIDC plugin initialized');

    
    const config: Config = { ...incomingConfig };
    const buttonPosition = opts.components?.position ?? 'beforeLogin';
    const existingComponents = config.admin?.components?.[buttonPosition] || [];

    // 👇 cast to any to silence missing `vite` type (runtime works fine)
    config.admin = {
      ...(config.admin || {}),
      ...( { vite: extendViteConfig(incomingConfig) } as any ),
      components: {
        ...(config.admin?.components || {}),
        [buttonPosition]: [
          ...existingComponents,
          opts.components?.Button ?? SignInButton,
        ],
      },
    };

    // 🧠 Stop here for admin-only build
    if (typeof window !== 'undefined') return config;

    // 🧠 Server-side logic
    (async () => {
      const session = (await import('express-session')).default;
      const passport = (await import('passport')).default;
      const OAuth2Strategy = (await import('passport-oauth2')).default;
      const createMemoryStore = (await import('memorystore')).default;

      const userCollectionSlug = opts.userCollection?.slug || 'users';
      const callbackPath = getCallbackPath(opts);
      const MemoryStore = createMemoryStore(session);

      // ⚠️ `root` prop removed in Payload 3; just omit it
      config.endpoints = [
        ...(config.endpoints || []),
        {
          path: opts.initPath,
          method: 'get',
          handler: passport.authenticate('oauth2'),
        },
        {
          path: callbackPath,
          method: 'get',
          handler: session({
            resave: false,
            saveUninitialized: false,
            secret: process.env.PAYLOAD_SECRET || 'unsafe',
            store: new MemoryStore({ checkPeriod: 86400000 }),
          }),
        },
        {
          path: callbackPath,
          method: 'get',
          handler: passport.authenticate('oauth2', { failureRedirect: '/' }),
        },
        {
          path: callbackPath,
          method: 'get',
          handler: loginHandler(
            userCollectionSlug,
            opts.redirectPathAfterLogin || '/admin',
          ),
        },
      ];

      passport.use(new OAuth2Strategy(opts, verify(opts)));
      passport.serializeUser((user: any, done: (err: any, id?: any) => void) =>
        done(null, user.id),
      );
      passport.deserializeUser(async (id: string, done: (err: any, user?: any) => void) => {
        try {
          const user = await payload.findByID({ collection: userCollectionSlug, id });
          done(null, user);
        } catch (err) {
          done(err);
        }
      });
    })();

    return config;
  };
