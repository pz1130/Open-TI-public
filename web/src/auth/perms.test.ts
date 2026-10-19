import { ME_ADMIN, ME_VIEWER } from "../test/fixtures";
import { can } from "./perms";

test("权限点数组表示满足任一即可", () => {
  expect(can(ME_VIEWER, "alerts:read")).toBe(true);
  expect(can(ME_ADMIN, "alerts:read")).toBe(false);
  expect(can(ME_ADMIN, ["alerts:read", "dashboard:default"])).toBe(true);
  expect(can(ME_VIEWER, ["connectors:read", "dashboard:default"])).toBe(false);
  expect(can(null, ["alerts:read"])).toBe(false);
});
