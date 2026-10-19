import { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router";
import { Providers } from "../App";

export function renderApp(ui: ReactElement, { route = "/" }: { route?: string } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return {
    client,
    ...render(
      <Providers client={client}>
        <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
      </Providers>,
    ),
  };
}
