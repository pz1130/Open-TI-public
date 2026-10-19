import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import SearchPage from "./SearchPage";
import { ME_ANALYST } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("检索文档并显示命中上下文", async () => {
  let query: string | null = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/documents", ({ request }) => {
      query = new URL(request.url).searchParams.get("q");
      return HttpResponse.json({
        items: [{
          id: 9,
          url: "https://news.example/a",
          title: "Bank approves loan",
          snippet: "",
          contexts: ["Sample Brand approved"],
          language: "en",
          source_name: "Example News",
          connectors: ["gdelt_doc"],
          published_at: "2026-10-02T08:00:00Z",
          first_seen: "2026-10-02T09:00:00Z",
          cluster_id: 9,
        }],
        next_cursor: null,
      });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SearchPage />);
  await user.type(await screen.findByPlaceholderText("检索标题、摘要与命中片段"), "Sample Brand{Enter}");
  const link = await screen.findByRole("link", { name: "Bank approves loan" });
  expect(link).toHaveAttribute("href", "https://news.example/a");
  expect(link).toHaveAttribute("rel", "noopener noreferrer");
  expect(screen.getByText("Sample Brand approved")).toBeInTheDocument();
  expect(query).toBe("Sample Brand");
});
