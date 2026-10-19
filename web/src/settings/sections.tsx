import type { ReactNode } from "react";
import AlertingTab from "./AlertingTab";
import CampaignsTab from "./CampaignsTab";
import OrganizationTab from "./OrganizationTab";
import RetentionTab from "./RetentionTab";
import RulesTab from "./RulesTab";
import SharingTab from "./SharingTab";
import SoftwareTab from "./SoftwareTab";
import TakedownTab from "./TakedownTab";
import TemplatesTab from "./TemplatesTab";
import TicketsTab from "./TicketsTab";
import VendorsTab from "./VendorsTab";
import ServicesTab from "./ServicesTab";
import MasterKeyTab from "./MasterKeyTab";
import BusinessSettingsTab from "./BusinessSettingsTab";
import UsersTab from "./UsersTab";
import AccessTab from "./AccessTab";
import ProjectsTab from "./ProjectsTab";

export type Section = {
  group: "monitor" | "notify" | "respond" | "platform" | "admin";
  items: { kind: string; perm?: string; element: ReactNode }[];
};

export const SECTIONS: Section[] = [
  { group: "monitor", items: [{ kind: "rules", perm: "rules:test", element: <RulesTab /> }, { kind: "campaigns", element: <CampaignsTab /> }, { kind: "vendors", element: <VendorsTab /> }, { kind: "software", element: <SoftwareTab /> }] },
  { group: "notify", items: [{ kind: "alerting", element: <AlertingTab /> }, { kind: "tickets", element: <TicketsTab /> }, { kind: "sharing", element: <SharingTab /> }] },
  { group: "respond", items: [{ kind: "takedown", element: <TakedownTab /> }, { kind: "takedown_templates", element: <TemplatesTab /> }] },
  { group: "platform", items: [{ kind: "organization", element: <OrganizationTab /> }, { kind: "retention", element: <RetentionTab /> }] },
  { group: "admin", items: [
    { kind: "users", perm: "users:write", element: <UsersTab /> },
    { kind: "access", perm: "access:write", element: <AccessTab /> },
    { kind: "projects", perm: "projects:write", element: <ProjectsTab /> },
    { kind: "master_key", perm: "config:write", element: <MasterKeyTab /> },
    { kind: "identity", perm: "config:write", element: <BusinessSettingsTab kind="identity" /> },
    { kind: "operations", perm: "config:write", element: <BusinessSettingsTab kind="operations" /> },
    { kind: "services", perm: "config:write", element: <ServicesTab /> },
  ] },
];
