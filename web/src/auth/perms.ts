import type { Me } from "../api/hooks";

/** perm 为数组时满足任一即可。 */
export function can(me: Me | null | undefined, perm: string | readonly string[]): boolean {
  if (!me) return false;
  return typeof perm === "string" ? me.permissions.includes(perm) : perm.some((p) => me.permissions.includes(p));
}
