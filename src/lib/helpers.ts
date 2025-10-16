import { oidcPluginOptions } from "../types.js";

export const getCallbackPath = (opts: oidcPluginOptions) => {
  return (
    opts.callbackPath ||
    (opts.callbackURL && new URL(opts.callbackURL).pathname) ||
    '/api/oidc/callback'
  );
};

/**
 * Returns true if a field directly stores data (vs. structural or UI fields)
 */
export function fieldAffectsData(field: any): boolean {
  if (!field) return false;
  // field has a name, and is not purely presentational
  return typeof field.name === 'string' && field.type !== 'ui' && field.type !== 'row' && field.type !== 'tabs';
}

/**
 * Returns true if a field contains nested subfields (like groups, arrays, blocks, tabs)
 */
export function fieldHasSubFields(field: any): boolean {
  return Array.isArray(field?.fields);
}