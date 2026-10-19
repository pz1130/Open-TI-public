import { Alert, Button, Card, Col, Collapse, Descriptions, Result, Row, Space, Spin, Tag, Timeline, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";
import { errorMessage } from "../api/client";
import { useAlert, useMe, useUpdateAlert } from "../api/hooks";
import { can } from "../auth/perms";
import DomainText from "../components/DomainText";
import { campaignLabel } from "../components/campaign";
import AttackTags from "../components/AttackTags";
import CodeLeakCard from "../components/CodeLeakCard";
import DocumentCard from "../components/DocumentCard";
import DisposalCard from "../components/DisposalCard";
import EvidencePanel from "../components/EvidencePanel";
import ExposureCard from "../components/ExposureCard";
import LeakPostCard from "../components/LeakPostCard";
import VulnerabilityCard from "../components/VulnerabilityCard";
import FeedbackForm from "../components/FeedbackForm";
import JsonBlock from "../components/JsonBlock";
import ScoreBreakdown from "../components/ScoreBreakdown";
import { fmtTime } from "../components/format";
import { AlertStatusTag, SeverityTag, WatchStateTag } from "../components/tags";

interface MatchReason {
  reason: string;
  token?: string;
  label?: string;
  where?: string;
}

export default function AlertDetailPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const alertId = Number(useParams().id);
  const me = useMe().data;
  const q = useAlert(alertId);
  const update = useUpdateAlert(alertId);
  if (q.isPending) return <Spin />;
  if (q.isError) return <Result status="error" title={errorMessage(q.error)} />;
  const d = q.data;
  const a = d.alert;
  const superseded = a.status === "superseded";
  const canTriage = can(me, "alerts:triage") && !superseded;
  const reasons = ((d.finding.match.reasons as MatchReason[] | undefined) ?? []).filter((r) => r && r.reason);
  const actions = canTriage && (
    <Space>
      {a.status === "open" && (
        <Button onClick={() => update.mutate({ status: "acknowledged" })}>{t("detail.acknowledge")}</Button>
      )}
      {a.status !== "closed" && <Button onClick={() => update.mutate({ status: "closed" })}>{t("detail.close")}</Button>}
      {["open", "acknowledged"].includes(a.status) && <Button onClick={() => update.mutate({ ignored: !a.ignored })}>{t(a.ignored ? "alerts.restore" : "alerts.ignore")}</Button>}
      {a.status === "closed" && <Button onClick={() => update.mutate({ status: "open" })}>{t("detail.reopen")}</Button>}
      {d.assignee !== me?.username && (
        <Button onClick={() => update.mutate({ assign_to_me: true })}>{t("detail.assignMe")}</Button>
      )}
    </Space>
  );
  return (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Card
        title={
          <Space>
            <Button onClick={() => navigate("/alerts")}>{t("common.back")}</Button>
            {t("detail.title", { id: a.id })}
            <SeverityTag value={a.severity} />
            <AlertStatusTag value={a.status} />
            {a.ignored && <Tag>{t("alerts.ignoredTag")}</Tag>}
          </Space>
        }
        extra={actions}
      >
        {superseded && <Alert type="info" showIcon message={t("detail.supersededNote")} style={{ marginBottom: 16 }} />}
        {update.isError && (
          <Alert type="error" showIcon message={t("common.error", { message: errorMessage(update.error) })} style={{ marginBottom: 16 }} />
        )}
        <Descriptions
          column={{ xs: 1, md: 2 }}
          items={[
            { key: "domain", label: t("alerts.col.domain"), children: <DomainText value={a.domain} /> },
            { key: "category", label: t("alerts.col.category"), children: t(`category.${a.category}`, { defaultValue: a.category }) },
            { key: "attack", label: t("attack.candidates"), children: <Space direction="vertical"><AttackTags techniques={a.attack_techniques} />{a.attack_techniques.length > 0 && <Typography.Text type="secondary">{t("attack.candidateNote")}</Typography.Text>}</Space> },
            { key: "score", label: t("detail.alertScore"), children: a.score },
            { key: "current-score", label: t("detail.currentScore"), children: d.finding.score },
            { key: "first", label: t("detail.firstSeen"), children: fmtTime(a.first_seen) },
            { key: "last", label: t("alerts.col.lastSeen"), children: fmtTime(a.last_seen) },
            { key: "sources", label: t("detail.sources"), children: a.sources.join(", ") },
            { key: "assignee", label: t("detail.assignee"), children: d.assignee ?? t("detail.unassigned") },
            {
              key: "notified",
              label: t("detail.notified"),
              children: a.notified_at ? fmtTime(a.notified_at) : t("detail.notNotified"),
            },
            {
              key: "watch",
              label: t("detail.watch"),
              children: d.watch ? (
                <Space>
                  <WatchStateTag value={d.watch.state} />
                  {t("detail.nextCheck", { time: fmtTime(d.watch.next_check_at) })}
                </Space>
              ) : (
                t("detail.notWatched")
              ),
            },
          ]}
        />
      </Card>
      {d.finding.category === "credential_exposure" && <ExposureCard alertId={a.id} />}
      {d.finding.category === "ransomware_mention" && <LeakPostCard match={d.finding.match} />}
      {d.finding.category === "vulnerability" && <VulnerabilityCard match={d.finding.match} />}
      {(d.finding.category === "secret_leak" || d.finding.category === "data_leak") && <CodeLeakCard match={d.finding.match} />}
      {["brand_mention", "negative_press", "fraud_scam", "threat_intel"].includes(d.finding.category) && (
        <DocumentCard match={d.finding.match} alertId={a.id} translationAvailable={d.translation_available && can(me, "evidence:read")} />
      )}
      <Row gutter={[16, 16]}>
        <Col xs={24} md={12}>
          <Card title={t("detail.breakdown")}>
            {a.score !== d.finding.score && <Alert type="info" showIcon message={t("detail.scoreChangedNote")} style={{ marginBottom: 16 }} />}
            <ScoreBreakdown breakdown={d.finding.score_breakdown} total={d.finding.score} />
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card title={t("detail.reasons")}>
            <Space direction="vertical">
              {reasons.map((r, i) => (
                <span key={`${r.reason}-${i}`}>
                  <Tag>{t(`reason.${r.reason}`, { defaultValue: r.reason })}</Tag>
                  <Typography.Text className="opti-mono">{[r.token, r.label, r.where].filter(Boolean).join(" · ")}</Typography.Text>
                </span>
              ))}
            </Space>
          </Card>
        </Col>
      </Row>
      {(() => {
        const context = (d.finding.match as { context?: Record<string, unknown> }).context;
        if (!context) return null;
        const { description, ...rest } = context;
        return (
          <Card title={t("detail.context")}>
            {typeof description === "string" && (
              <Descriptions column={1} items={[{ key: "desc", label: t("detail.reportDescription"), children: description }]} />
            )}
            <JsonBlock value={rest} />
          </Card>
        );
      })()}
      <EvidencePanel
        evidence={d.evidence}
        canView={can(me, "evidence:read")}
        enrichment={d.enrichment}
        alertId={d.alert.id}
        canUpload={canTriage}
        platform={typeof d.finding.match.platform === "string"}
      />
      {d.campaign && (
        <Card title={t("detail.campaign")}>
          <Space>
            <Link to={`/campaigns/${d.campaign.id}`}>{campaignLabel(t, d.campaign)}</Link>
            {d.campaign.member_state === "pending" && <Tag color="gold">{t("detail.campaignPending")}</Tag>}
          </Space>
        </Card>
      )}
      {can(me, "evidence:read") && d.related_alerts.length > 0 && (
        <Card title={t("detail.relatedAlerts")}>
          <Space direction="vertical">
            <Typography.Text type="secondary">{t("detail.relatedReview")}</Typography.Text>
            {d.related_alerts.map((related) => (
              <Space key={related.id} wrap>
                <Link to={`/alerts/${related.id}`}>#{related.id}</Link>
                <DomainText value={related.domain} />
                <SeverityTag value={related.severity} />
                <AlertStatusTag value={related.status} />
                {related.signals.map((signal) => (
                  <Tag key={signal}>{t(`detail.relatedSignal.${signal}`)}</Tag>
                ))}
                <Typography.Text type="secondary">{fmtTime(related.last_seen)}</Typography.Text>
              </Space>
            ))}
          </Space>
        </Card>
      )}
      {(can(me, "takedown:read") || can(me, "tickets:push") || can(me, "evidence:export")) && <DisposalCard detail={d} />}

      {canTriage && <FeedbackForm alertId={a.id} allowSuppress={d.entity_type === "domain"} />}
      {d.feedback.length > 0 && (
        <Card title={t("detail.feedback")}>
          <Timeline
            items={d.feedback.map((f) => ({
              children: `${fmtTime(f.created_at)} · ${f.username} · ${t(`verdict.${f.verdict}`, { defaultValue: f.verdict })}${f.reason ? ` · ${f.reason}` : ""}`,
            }))}
          />
        </Card>
      )}
      <Card title={t("detail.enrichment")}>
        <Collapse
          items={Object.entries(d.enrichment).map(([name, entry]) => {
            const e = (entry ?? {}) as { data?: unknown; fetched_at?: string };
            return {
              key: name,
              label: `${name} · ${t("detail.fetchedAt", { time: fmtTime(e.fetched_at) })}`,
              children: <JsonBlock value={e.data ?? entry} />,
            };
          })}
        />
      </Card>
      <Card title={t("detail.observations")}>
        <Timeline
          items={d.observations.map((o) => ({
            children: `${fmtTime(o.observed_at)} · ${o.connector_id} · ${o.score}`,
          }))}
        />
      </Card>
      {d.history.length > 0 && (
        <Card title={t("detail.history")}>
          <Space direction="vertical">
            {d.history.map((h) => (
              <Space key={h.id}>
                <Link to={`/alerts/${h.id}`}>#{h.id}</Link>
                <SeverityTag value={h.severity} />
                <AlertStatusTag value={h.status} />
                {fmtTime(h.created_at)}
              </Space>
            ))}
          </Space>
        </Card>
      )}
    </Space>
  );
}
