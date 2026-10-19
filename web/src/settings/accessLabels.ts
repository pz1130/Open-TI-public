import type { TFunction } from "i18next";
import type { AccessRole, PermissionSet } from "../api/access";

export function roleLabel(t: TFunction, role: AccessRole): string {
  return role.builtin ? t(`shell.role.${role.name}`, { defaultValue: role.display_name }) : role.display_name;
}

export function setLabel(t: TFunction, set: PermissionSet): string {
  return set.builtin ? t(`access.groups.${set.name.replace("builtin_", "")}`, { defaultValue: set.display_name }) : set.display_name;
}

export function permissionLabel(t: TFunction, id: string, description: string): string {
  return t(`access.permissions.${id}`, { nsSeparator: false, defaultValue: description });
}
