import type { Config, Payload, PayloadHandler, PayloadRequest } from 'payload'
import { loginHandler } from './lib/login.js'
import { verify } from './lib/oauth/verify.js'
import { getCallbackPath } from './lib/helpers.js'
import { extendViteConfig } from './lib/webpack.js'
import type { oidcPluginOptions, ResolvePayloadCallback } from './types.js'
import crypto from 'crypto'
import path from 'path'
import { fileURLToPath } from 'url'

// ensure proper __dirname resolution for ESM
const filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(filename)

export const oidcPlugin =
  (opts: oidcPluginOptions) =>
  (incomingConfig: Config): Config => {
    let payload_instance: Payload

    const callbackPath = getCallbackPath(opts)
    const userCollectionSlug = opts.userCollection?.slug || 'users'

    // --- Server-side setup (Next.js compatible) ---
    if (typeof window === 'undefined') {
      // --- OIDC Sign-in ---
      const initHandler: PayloadHandler = async (req: PayloadRequest) => {
        try {
          const state = crypto.randomBytes(16).toString('hex')
          const redirectURL = new URL(opts.authorizationURL)
          redirectURL.searchParams.set('client_id', opts.clientID)
          redirectURL.searchParams.set('redirect_uri', opts.callbackURL)
          redirectURL.searchParams.set('response_type', 'code')
          redirectURL.searchParams.set('scope', opts.scope)
          redirectURL.searchParams.set('state', state)

          return new Response(null, {
            status: 302,
            headers: {
              Location: redirectURL.toString(),
              'Set-Cookie': `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`,
            },
          })
        } catch (err) {
          console.error('[🔒oidc-plugin] ❌ initHandler error:', err)
          return new Response('OIDC init error', { status: 500 })
        }
      }

      interface HydraTokenResponse {
        access_token: string
        expires_in: number
        id_token?: string
        refresh_token?: string
        scope: string
        token_type: 'bearer' | 'Bearer'
      }

      // --- OIDC Callback ---
      const callbackHandler: PayloadHandler = async (req: PayloadRequest) => {
        try {
          if (payload_instance == null) {
            if (req.payload == null) {
              return new Response('Payload not available', { status: 500 })
            }
          } else {
            req.payload = payload_instance
          }

          const rawUrl = req.url ?? ''
          const url = new URL(rawUrl, 'http://localhost')
          const code = url.searchParams.get('code')

          if (!code) {
            return new Response('Missing code', { status: 400 })
          }

          const tokenRes = await fetch(opts.tokenURL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              grant_type: 'authorization_code',
              code,
              redirect_uri: opts.callbackURL,
              client_id: opts.clientID,
              client_secret: opts.clientSecret,
            }),
          })

          if (!tokenRes.ok) {
            const text = await tokenRes.text()
            console.error('[🔒oidc-plugin] ❌ Token exchange failed:', text)
            return new Response('OIDC token exchange failed', { status: 500 })
          }

          const tokenData = (await tokenRes.json()) as HydraTokenResponse

          if (opts.userinfo == null) throw 'You have not configured a mapper for the user.'
          const user = await opts.userinfo(tokenData.access_token, req.payload)

          const slug = (opts.userCollection?.slug as 'users') || 'users'
          const home = opts.redirectPathAfterLogin || '/admin'

          return loginHandler(slug, home, user, opts.debug == true)(req)
        } catch (err) {
          console.error('[🔒oidc-plugin] ❌ callbackHandler error:', err)
          return new Response('Callback error', { status: 500 })
        }
      }

      // --- Register routes (Next/Payload-native, not Express) ---
      incomingConfig.endpoints = [
        ...(incomingConfig.endpoints || []),
        { path: opts.initPath, method: 'get', handler: initHandler },
        { path: callbackPath, method: 'get', handler: callbackHandler },
      ]
    }

    // --- Admin UI Integration ---
    const defaultSignInButton = {
      path: path.resolve(__dirname, './components/SignInButton/SignInButton.js'),
    }

    const config: Config = {
      ...incomingConfig,
      admin: {
        ...(incomingConfig.admin || {}),
        ...({ vite: extendViteConfig(incomingConfig) } as any),
        components: {
          ...(incomingConfig.admin?.components || {}),
          [opts.components?.position ?? 'beforeLogin']: [
            ...(incomingConfig.admin?.components?.[opts.components?.position ?? 'beforeLogin'] || []),
            opts.components?.Button ?? defaultSignInButton,
          ],
        },
      },
    }

    config.onInit = async (payload) => {
      if (payload) {
        payload.logger.info('☑️  OIDC plugin initializing passport.')
        const passport = require('passport')
        const OAuth2Strategy = require('passport-oauth2')
        payload_instance = payload

        const resolveUser: ResolvePayloadCallback = () => payload_instance
        passport.use(new OAuth2Strategy(opts, verify(opts, resolveUser)))
      }
    }

    return config
  }
