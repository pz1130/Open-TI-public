import { useQuery } from "@tanstack/react-query";
import { Button, Tooltip } from "antd";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { api, setActiveProject, unwrap } from "../api/client";
import { reloadProject } from "./projectContext";

export default function ProjectStatus({ admin }: { admin: boolean }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const previous = useRef<string | undefined>(undefined);
  const q = useQuery({
    queryKey: ["active-project"],
    queryFn: async () => unwrap(await api.GET("/api/v1/projects/current")),
    refetchInterval: 5000,
    refetchOnWindowFocus: "always",
  });
  useEffect(() => {
    if (!q.data) return;
    setActiveProject(q.data.project_id);
    if (previous.current !== undefined && previous.current !== q.data.project_id) reloadProject(admin);
    previous.current = q.data.project_id;
  }, [q.data, admin]);
  if (!q.data) return null;
  const label = t("settings.projects.current", { project: q.data.project_id });
  return <span className="oti-project-status"><Tooltip title={label}>
    {admin ? <Button size="small" onClick={() => navigate("/settings/projects")}>{label}</Button> : <span>{label}</span>}
  </Tooltip></span>;
}
