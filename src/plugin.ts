import type { Config, Payload, PayloadHandler, PayloadRequest } from 'payload';
import SignInButton from './components/SignInButton/SignInButton';
import { loginHandler } from './lib/login';
import { verify } from './lib/oauth/verify';
import { getCallbackPath } from './lib/helpers';
import { extendViteConfig } from './lib/webpack';
import type { oidcPluginOptions } from './types';
import crypto from 'crypto';
import { json } from 'stream/consumers';

export const oidcPlugin =
  (opts: oidcPluginOptions) =>
  (incomingConfig: Config): Config => {
    console.log('[payload-plugin-oidc] → Initializing OIDC plugin');

    let payload_instance: Payload | null = null;

    const callbackPath = getCallbackPath(opts);
    const userCollectionSlug = opts.userCollection?.slug || 'users';
    console.log(
      '[payload-plugin-oidc]',
      'userCollection:',
      userCollectionSlug,
      'initPath:',
      opts.initPath,
      'callbackPath:',
      callbackPath,
    );

    // --- Server-side setup (Next.js compatible) ---
    if (typeof window === 'undefined') {
      console.log('[payload-plugin-oidc] Running server-side setup...');
      const passport = require('passport');
      const OAuth2Strategy = require('passport-oauth2');

      console.log('[payload-plugin-oidc] Registering OAuth2 strategy...');
      console.log('[payload-plugin-oidc] passport config -> ', JSON.stringify(opts));
      passport.use(new OAuth2Strategy(opts, verify(opts)));

      // --- OIDC Sign-in ---
      const initHandler: PayloadHandler = async (req: PayloadRequest) => {
        console.log('[payload-plugin-oidc] /oidc/signin route hit');

        try {
          const state = crypto.randomBytes(16).toString('hex'); // 32-char random hex (strong entropy)
          const redirectURL = new URL(opts.authorizationURL);
          redirectURL.searchParams.set('client_id', opts.clientID);
          redirectURL.searchParams.set('redirect_uri', opts.callbackURL);
          redirectURL.searchParams.set('response_type', 'code');
          redirectURL.searchParams.set('scope', opts.scope);
          redirectURL.searchParams.set('state', state);

          console.log('[payload-plugin-oidc] Redirecting to:', redirectURL);

          return new Response(null, {
            status: 302,
            headers: {
              Location: redirectURL.toString(),
              'Set-Cookie': `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`, // 5 min lifetime
            },
          });
        } catch (err) {
          console.error('[payload-plugin-oidc] ❌ initHandler error:', err);
          return new Response('OIDC init error', { status: 500 });
        }
      };

      interface HydraTokenResponse {
        access_token: string;
        expires_in: number;
        id_token?: string; // optional depending on grant type
        refresh_token?: string; // optional given refresh type
        scope: string;
        token_type: 'bearer' | 'Bearer';
      }

      // --- OIDC Callback ---
      const callbackHandler: PayloadHandler = async (req: PayloadRequest) => {
        console.log('[payload-plugin-oidc] /oidc/callback route hit');
        try {
          if (payload_instance == null) {
            console.error('[payload-plugin-oidc] ❌ global payload is undefined');
            if (req.payload == null) {
              console.error('[payload-plugin-oidc] ❌ req.payload is undefined');
              return new Response('Payload not available', { status: 500 });
            } else {
              console.error('[payload-plugin-oidc] ☑️ payload IS in the req object!');
            }
          } else {
            req.payload = payload_instance;
            console.error('[payload-plugin-oidc] ☑️ WE GOT PAYLOAD!');
          }

          const rawUrl = req.url ?? '';
          const url = new URL(rawUrl, 'http://localhost');
          const code = url.searchParams.get('code');
          console.log('[payload-plugin-oidc] received code:', code);

          if (!code) {
            console.error('[payload-plugin-oidc] ❌ Missing code');
            return new Response('Missing code', { status: 400 });
          }

          const tokenRes = await fetch(opts.tokenURL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
              grant_type: 'authorization_code',
              code: code,
              redirect_uri: opts.callbackURL,
              client_id: opts.clientID,
              client_secret: opts.clientSecret,
            }),
          });

          if (!tokenRes.ok) {
            const text = await tokenRes.text();
            console.error('[payload-plugin-oidc] ❌ Token exchange failed:', text);
            return new Response('OIDC token exchange failed', { status: 500 });
          }

          const tokenData = (await tokenRes.json()) as HydraTokenResponse;
          console.log('[payload-plugin-oidc] ✅ Token response:', tokenData);

          // TODO: Fetch userinfo here, or pass tokenData to verify()
          // Example:
          if (opts.userinfo == null) {
            throw 'You have not configured a mapper for the user.';
          }
          let user = await opts.userinfo(tokenData.access_token);

          // check if the user already exists
          let slug = (opts.userCollection?.slug as 'users') || 'users';
          let home = opts.redirectPathAfterLogin || '/admin';

          // Ensure Payload is initialized before using it (important for Next.js)
          return loginHandler(slug, home, user)(req);

          // return new Response('OIDC login complete', { status: 200 });
        } catch (err) {
          console.error('[payload-plugin-oidc] ❌ callbackHandler error:', err);
          return new Response('Callback error', { status: 500 });
        }
      };

      // --- Register routes (Next/Payload-native, not Express) ---
      console.log('[payload-plugin-oidc] Registering endpoints...');
      incomingConfig.endpoints = [
        ...(incomingConfig.endpoints || []),
        { path: opts.initPath, method: 'get', handler: initHandler },
        { path: callbackPath, method: 'get', handler: callbackHandler },
      ];
      console.log(
        '[payload-plugin-oidc] ✅ Endpoints registered:',
        opts.initPath,
        'and',
        callbackPath,
      );
    }

    // --- Admin UI Integration ---
    const config: Config = {
      ...incomingConfig,
      admin: {
        ...(incomingConfig.admin || {}),
        // 🩹 TypeScript-safe hack: add vite integration without breaking the type system
        ...({ vite: extendViteConfig(incomingConfig) } as any),
        components: {
          ...(incomingConfig.admin?.components || {}),
          [opts.components?.position ?? 'beforeLogin']: [
            ...(incomingConfig.admin?.components?.[opts.components?.position ?? 'beforeLogin'] ||
              []),
            opts.components?.Button ?? SignInButton,
          ],
        },
      },
    };

    config.onInit = async (payload) => {
      if (payload) {        
        payload.logger.info(' ☑️ ☑️ Plugin Has Payload!');
        payload_instance = payload;
      }
    };

    console.log('[payload-plugin-oidc] Plugin setup complete ✅');
    return config;
  };
