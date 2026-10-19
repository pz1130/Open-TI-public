import { ApiError, errorMessage } from "./client";

test("配置校验错误显示出错的位置与原因", () => {
  const e = new ApiError(422, { detail: { errors: [
    { path: "connectors.otx.config", message: "max_queries 超过上限 20", line: null },
    { path: "", message: "该版本无法解析", line: null },
  ] } });
  expect(errorMessage(e)).toBe("connectors.otx.config：max_queries 超过上限 20；该版本无法解析");
});

test("字符串与 message 形式的错误不变", () => {
  expect(errorMessage(new ApiError(409, { detail: "alert superseded by a newer alert" }))).toBe("alert superseded by a newer alert");
  expect(errorMessage(new ApiError(400, { detail: { message: "bad" } }))).toBe("bad");
  expect(errorMessage(new ApiError(500, null))).toBe("HTTP 500");
});
