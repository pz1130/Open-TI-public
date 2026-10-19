import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { PaginationProps } from "antd";

export const listPagination: PaginationProps = {
  defaultPageSize: 20,
  showSizeChanger: true,
  pageSizeOptions: [10, 20, 50, 100],
};

/** Reset the page before querying a different search, filter or parent record. */
export function usePagination(scope: unknown = null) {
  const { t } = useTranslation();
  const key = JSON.stringify(scope);
  const [state, setState] = useState({ key, page: 1, pageSize: 20 });
  const page = state.key === key ? state.page : 1;
  if (state.key !== key) setState({ ...state, key, page: 1 });
  return {
    page,
    pageSize: state.pageSize,
    config(total?: number): PaginationProps {
      if (total !== undefined && page > Math.max(1, Math.ceil(total / state.pageSize))) {
        setState({ ...state, key, page: Math.max(1, Math.ceil(total / state.pageSize)) });
      }
      return {
        ...listPagination,
        showSizeChanger: { "aria-label": t("common.pageSize") },
        current: page,
        pageSize: state.pageSize,
        total: total ?? 0,
        showTotal: (count) => t("common.totalItems", { count }),
        onChange: (next, size) => setState({ key, page: size !== state.pageSize ? 1 : next, pageSize: size }),
      };
    },
  };
}
