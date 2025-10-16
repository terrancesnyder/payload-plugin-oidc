import { Response } from 'express';
import jwt from 'jsonwebtoken';
import payload, { generateCookie, generatePayloadCookie } from 'payload';
import type { PayloadHandler, PayloadRequest, SanitizedCollectionConfig, Field } from 'payload';

type GetCookieExpirationArgs = {
  /*
    The number of seconds until the cookie expires
    @default 7200 seconds (2 hours)
  */
  seconds: number;
};
export const getCookieExpiration = ({ seconds = 7200 }: GetCookieExpirationArgs) => {
  const currentTime = new Date();
  currentTime.setSeconds(currentTime.getSeconds() + seconds);
  return currentTime;
};

/**
 * Express-style handler for OIDC login redirect
 */
export const loginHandler = (
  userCollectionSlug: string,
  redirectPathAfterLogin: string,
  oidcUser: any, // renamed for clarity
  debug: boolean,
): PayloadHandler => {
  // ✅ Return a fetch-compatible handler
  return async (req: PayloadRequest): Promise<globalThis.Response> => {
    // find the user configuration
    const collectionConfig = req.payload.collections[userCollectionSlug].config;

    if (!oidcUser.email) {
      console.error('[🔒oidc-plugin] user object does not have email attribute');
      throw '[🔒oidc-plugin] user object does not have email attribute';
    }

    // --- 1. Find or create user ---
    const existing = await req.payload.find({
      collection: userCollectionSlug,
      where: {
        email: { equals: oidcUser.email },
      },
    });

    // check if user already exists, if not lets automatically create them
    // and we apparently MUST set a password which later we'll let the user
    // change, but for now its fine.
    let user = existing?.docs?.[0];
    if (!user) {
      user = await req.payload.create({
        collection: userCollectionSlug,
        data: {
          email: oidcUser.email,
          name: oidcUser.display_name,
          display_name: oidcUser.display_name,
          given_name: oidcUser.given_name,
          family_name: oidcUser.family_name,
          picture: oidcUser.picture,
          sub: oidcUser.sub,
          iss: oidcUser.iss,
          password: 'my_password_1234',
        },
      });
    }

    const headers = new Headers();

    // must call login to generate a session and get back our token
    const loginResult = await req.payload.login({
      collection: userCollectionSlug,
      data: {
        email: user.email,
        password: 'my_password_1234',
      },
      req,
    });

    if (loginResult.token != null) {
      const cookieHeaderLogin = generatePayloadCookie({
        collectionAuthConfig: collectionConfig.auth,
        cookiePrefix: req.payload.config.cookiePrefix,
        token: loginResult.token,
      });
      headers.append('Set-Cookie', cookieHeaderLogin);
    } else {
      throw 'User could not be logged in.'
    }

    // --- 5. Return a Response with the Set-Cookie header and optional redirect ---
    // headers.append('Set-Cookie', cookieHeaderManual);
    headers.set('Location', redirectPathAfterLogin);
    headers.set('Content-Type', 'text/plain');

    // If redirect is intended, use 302; otherwise return 200 OK
    return new Response('AOK', {
      status: redirectPathAfterLogin ? 302 : 200,
      headers,
    });
  };
};

/**
 * Build the object of fields to include in JWT
 */
export const getFieldsToSign = (
  collectionConfig: SanitizedCollectionConfig,
  user: Record<string, any>,
) => {
  return collectionConfig.fields.reduce(
    (signed: Record<string, any>, field: Field) => {
      const result = { ...signed };

      // safely check for subfields
      if (Array.isArray((field as any).fields)) {
        (field as any).fields.forEach((sub: any) => {
          if (sub && 'saveToJWT' in sub && sub.saveToJWT) {
            result[sub.name] = user[sub.name];
          }
        });
      }

      if ('saveToJWT' in field && field.saveToJWT) {
        result[(field as any).name] = user[(field as any).name];
      }

      return result;
    },
    {
      email: user.email,
      id: user.id,
      collection: collectionConfig.slug,
    },
  );
};
