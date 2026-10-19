import { can } from "../auth/perms";
import { ME_ADMIN, ME_ANALYST, ME_VIEWER } from "../test/fixtures";
import { groupOf } from "../shell/navGroups";
import { PAGES } from "./registry";

test("管理员能够从监测导航进入证书页，无需授予告警权限", () => {
  const page = PAGES.find((p) => p.path === "certificates")!;
  expect(page.nav).toBe(true);
  expect(groupOf(page)).toBe("monitor");
  for (const me of [ME_ADMIN, ME_ANALYST, ME_VIEWER]) expect(can(me, page.perm)).toBe(true);
  expect(can(ME_ADMIN, PAGES.find((p) => p.path === "alerts")!.perm)).toBe(false);
});
