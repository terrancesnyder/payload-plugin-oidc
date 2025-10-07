import type { Auth } from 'payload'

import { cookies as getCookies } from 'next/headers.js'
import { generatePayloadCookie } from 'payload'

type SetPayloadAuthCookieArgs = {
  authConfig: Auth
  cookiePrefix: string
  token: string
}

export async function setPayloadAuthCookie({
  authConfig,
  cookiePrefix,
  token,
}: SetPayloadAuthCookieArgs): Promise<void> {
  const cookies = await getCookies()

  const cookieExpiration = authConfig.tokenExpiration
    ? new Date(Date.now() + authConfig.tokenExpiration)
    : undefined

  const payloadCookie = generatePayloadCookie({
    collectionAuthConfig: authConfig,
    cookiePrefix,
    expires: cookieExpiration,
    returnCookieAsObject: true,
    token,
  })

  console.log('[payload-oidc-plugin] cookie', payloadCookie);

  if (payloadCookie.value) {
    console.log('[payload-oidc-plugin] set cookie', payloadCookie);
    cookies.set(payloadCookie.name, payloadCookie.value, {
      domain: authConfig.cookies.domain,
      expires: payloadCookie.expires ? new Date(payloadCookie.expires) : undefined,
      httpOnly: true,
      sameSite: (typeof authConfig.cookies.sameSite === 'string'
        ? authConfig.cookies.sameSite.toLowerCase()
        : 'lax') as 'lax' | 'none' | 'strict',
      secure: authConfig.cookies.secure || false,
    })
  }
}