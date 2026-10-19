import { http, HttpResponse } from "msw";
import { server } from "../test/server";
import { ApiError } from "./client";
import { requestWatchCheck, WatchCheckUnconfirmed } from "./watchChecks";

test.each([
  null,
  { status: "queued", watch_id: 9, request_id: "another-domain" },
  { status: "queued", watch_id: 4 },
  { status: "failed", watch_id: 4, request_id: "failed" },
])("未收到对应域名的排队回执时不认定成功：%j", async (body) => {
  server.use(http.post("*/api/v1/watchlist/4/check", () => body === null
    ? new HttpResponse(null, { status: 202 })
    : HttpResponse.json(body, { status: 202 })));
  await expect(requestWatchCheck(4)).rejects.toBeInstanceOf(WatchCheckUnconfirmed);
});

test("服务端明确拒绝排队时保留 HTTP 错误", async () => {
  server.use(http.post("*/api/v1/watchlist/4/check", () => HttpResponse.json({ detail: "failed to queue watch check" }, { status: 503 })));
  await expect(requestWatchCheck(4)).rejects.toEqual(new ApiError(503, { detail: "failed to queue watch check" }));
});
