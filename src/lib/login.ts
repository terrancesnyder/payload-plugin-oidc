import { Response } from 'express';
import jwt from 'jsonwebtoken';
import payload from 'payload';
import type { Config, Field, PayloadRequest, SanitizedCollectionConfig } from 'payload';
import { fieldAffectsData, fieldHasSubFields } from './helpers';

/**
 * Returns a Date object representing when a cookie should expire
 */
function getCookieExpiration(seconds: number): Date {
  const exp = new Date();
  exp.setTime(exp.getTime() + seconds * 1000);
  return exp;
}

/**
 * Express-style handler for OIDC login redirect
 */
export const loginHandler =
  (userCollectionSlug: string, redirectPathAfterLogin: string) =>
  async (req: PayloadRequest, res: Response) => {
    const collectionConfig = payload.collections[userCollectionSlug].config;
    const user = JSON.parse(JSON.stringify(req.user));

    const fieldsToSign = getFieldsToSign(collectionConfig, user);

    const token = jwt.sign(fieldsToSign, payload.secret, {
      expiresIn: collectionConfig.auth.tokenExpiration,
    });

    res.cookie(`${payload.config.cookiePrefix}-token`, token, {
      path: '/',
      httpOnly: true,
      expires: getCookieExpiration(collectionConfig.auth.tokenExpiration),
      secure: collectionConfig.auth.cookies.secure,
      // sameSite: collectionConfig.auth.cookies.sameSite,
      domain: collectionConfig.auth.cookies.domain || undefined,
    });

    return res.redirect(redirectPathAfterLogin);
  };

/**
 * Build the object of fields to include in JWT
 */
const getFieldsToSign = (
  collectionConfig: SanitizedCollectionConfig,
  user: Record<string, any>,
) => {
  return collectionConfig.fields.reduce((signed: Record<string, any>, field: Field) => {
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
  }, {
    email: user.email,
    id: user.id,
    collection: collectionConfig.slug,
  });
};
