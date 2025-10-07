import { Response } from 'express';
import jwt from 'jsonwebtoken';
import payload, { generateCookie, generatePayloadCookie } from 'payload';
import type { PayloadHandler, PayloadRequest, SanitizedCollectionConfig, Field } from 'payload';
import { fieldAffectsData, fieldHasSubFields } from './helpers';
import { setPayloadAuthCookie } from './setPayloadAuthCookie';

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
): PayloadHandler => {
  // ✅ Return a fetch-compatible handler
  return async (req: PayloadRequest): Promise<globalThis.Response> => {
    // find the user configuration
    const collectionConfig = req.payload.collections[userCollectionSlug].config;
    console.log('[payload-oidc-plugin] user', oidcUser);

    console.log('[payload-oidc-plugin] does payload exits? ' + (req.payload ? 'true' : 'false'));

    if (!oidcUser.email) {
      console.error('[payload-oidc-plugin] user object does not have email attribute');
      throw '[payload-oidc-plugin] user object does not have email attribute';
    }

    // create the user if they dont exist
    console.log('[payload-oidc-plugin] try to find user with email', oidcUser.email);
    // --- 1. Find or create user ---
    const existing = await req.payload.find({
      collection: userCollectionSlug,
      where: {
        email: { equals: oidcUser.email },
      },
    });

    let user = existing?.docs?.[0];
    if (!user) {
      console.log('[payload-oidc-plugin] creating a new user', oidcUser.email);
      user = await req.payload.create({
        collection: userCollectionSlug,
        data: {
          email: oidcUser.email,
          displayName: oidcUser.displayName,
          givenName: oidcUser.givenName,
          familyName: oidcUser.familyName,
          oidcSub: oidcUser.sub,
          oidcIss: oidcUser.iss,
        },
      });
    }

    // sign the token to keep compliant with payload cms
    const fieldsToSign = getFieldsToSign(collectionConfig, oidcUser);
    console.log('[payload-oidc-plugin] fieldsToSign', fieldsToSign);
    const token = jwt.sign(fieldsToSign, req.payload.secret, {
      expiresIn: collectionConfig.auth.tokenExpiration,
    });
    console.log('[payload-oidc-plugin] token', token);

    // // apply the cookie
    // res.cookie(`${payload.config.cookiePrefix}-token`, token, {
    //   path: '/',
    //   httpOnly: true,
    //   expires: getCookieExpiration({ seconds: collectionConfig.auth.tokenExpiration }),
    //   secure: collectionConfig.auth.cookies.secure,
    //   // sameSite: collectionConfig.auth.cookies.sameSite,
    //   domain: collectionConfig.auth.cookies.domain || undefined,
    // });

    // res.cookie(`${payload.config.cookiePrefix}-token`, token, {
    //   path: '/',
    //   httpOnly: true,
    //   expires: getCookieExpiration({ seconds: collectionConfig.auth.tokenExpiration }),
    //   secure: collectionConfig.auth.cookies.secure,
    //   // sameSite: collectionConfig.auth.cookies.sameSite,
    //   domain: collectionConfig.auth.cookies.domain || undefined,
    // });

    // --- 3. Generate Payload-compatible cookie header ---
    const cookieHeader = generatePayloadCookie({
      collectionAuthConfig: collectionConfig.auth,
      cookiePrefix: req.payload.config.cookiePrefix,
      token,
    });

    // --- 4. Apply Set-Cookie header manually (like Payload core does) ---
    // res.setHeader('Set-Cookie', cookieHeader);
    console.log('[payload-oidc-plugin] set cookie', cookieHeader);

    // let cookie = generateCookie({
    //   name: `${req.payload.config.cookiePrefix}-token`,
    //   domain: undefined, // collectionAuthConfig.cookies.domain ?? undefined,
    //   expires: getCookieExpiration({ seconds: collectionConfig.auth.tokenExpiration }),
    //   httpOnly: true,
    //   path: '/',
    //   returnCookieAsObject: true, // returnCookieAsObject
    //   sameSite,
    //   secure: false, //collectionAuthConfig.cookies.secure,
    //   value: token,
    // });

    console.log('[payload-oidc-plugin] ✅ all is good we are redirecting.');

    //
    // return res.redirect(redirectPathAfterLogin);
    // new Response('OIDC login complete', { status: 200 });

    // --- 5. Return a Response with the Set-Cookie header and optional redirect ---
    const headers = new Headers({
      'Set-Cookie': cookieHeader, // generated above by generatePayloadCookie()
      'Content-Type': 'text/plain',
    });

    // If you want to redirect:
    headers.set('Location', redirectPathAfterLogin);

    // If redirect is intended, use 302; otherwise return 200 OK
    return new Response('OIDC login complete', {
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
