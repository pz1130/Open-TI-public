import { usePagination } from "../components/pagination";
import { Card, Input, List, Pagination, Space, Tag, Typography } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useDocuments } from "../api/hooks";
import QueryError from "../components/QueryError";
import { fmtTime } from "../components/format";

export default function SearchPage() {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const paging = usePagination(query);
  const results = useDocuments({ q: query }, paging.page, paging.pageSize);
  const items = results.data?.items ?? [];
  return (
    <Card title={t("search.title")}>
      <Space direction="vertical" style={{ width: "100%" }}>
        <Input.Search
          allowClear
          enterButton
          placeholder={t("search.placeholder")}
          onSearch={(value) => setQuery(value.trim())}
        />
        <Typography.Text type="secondary">{t("search.note")}</Typography.Text>
        <QueryError error={results.error} />
        <List
          loading={results.isPending}
          dataSource={items}
          locale={{ emptyText: t("search.empty") }}
          renderItem={(document) => (
            <List.Item key={document.id}>
              <Space direction="vertical" style={{ width: "100%" }}>
                <Space wrap>
                  {document.url ? (
                    <a href={document.url} target="_blank" rel="noopener noreferrer">
                      {document.title || document.url}
                    </a>
                  ) : (
                    <strong>{document.title}</strong>
                  )}
                  {document.language && <Tag>{document.language}</Tag>}
                  <Typography.Text type="secondary">
                    {[document.source_name, fmtTime(document.published_at ?? document.first_seen)]
                      .filter(Boolean).join(" · ")}
                  </Typography.Text>
                </Space>
                {document.contexts.map((context) => (
                  <Typography.Text key={context} type="secondary">{context}</Typography.Text>
                ))}
              </Space>
            </List.Item>
          )}
        />
        <Pagination {...paging.config(results.data?.total)} />
      </Space>
    </Card>
  );
}
