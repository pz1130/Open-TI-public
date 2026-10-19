import { Alert, Button, Form, Input, Space, Spin } from "antd";
import { CheckOutlined, LockOutlined, UserOutlined } from "@ant-design/icons";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useSearchParams } from "react-router";
import { oidcStartUrl, useAuthProviders, useLogin } from "../api/hooks";
import LanguageSwitch from "../components/LanguageSwitch";
import ThemeSwitch from "../components/ThemeSwitch";
import Radar from "../shell/Radar";
import ScopeEmblem from "../shell/ScopeEmblem";

interface LoginForm {
  username: string;
  password: string;
}

const LOGIN_ERRORS = new Set([
  "unavailable", "cancelled", "state", "token", "id_token", "too_many_groups", "no_role", "username_conflict", "disabled",
]);

function LocalForm({ primary }: { primary: boolean }) {
  const { t } = useTranslation();
  const login = useLogin();
  return (
    <Form<LoginForm> name="login" layout="vertical" onFinish={(v) => login.mutate(v)} requiredMark={false}>
      <Form.Item label={t("login.username")} name="username" rules={[{ required: true }]}>
        <Input size="large" prefix={<UserOutlined className="oti-input-icon" />} autoComplete="username" autoFocus placeholder="operator_id" />
      </Form.Item>
      <Form.Item label={t("login.password")} name="password" rules={[{ required: true }]}>
        <Input.Password size="large" prefix={<LockOutlined className="oti-input-icon" />} autoComplete="current-password" placeholder="••••••••••••" />
      </Form.Item>
      <Space direction="vertical" style={{ width: "100%" }}>
        {login.isError && <Alert type="error" showIcon message={t("login.failed")} />}
        <Button className="oti-login-submit" type={primary ? "primary" : "default"} htmlType="submit" block size="large" loading={login.isPending}>
          {t("login.submit")}
        </Button>
      </Space>
    </Form>
  );
}

export default function LoginPage() {
  const { t } = useTranslation();
  const providers = useAuthProviders();
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const [showLocal, setShowLocal] = useState(false);
  const error = params.get("login_error");
  // 登录后回到当前页面；根路径上的查询参数只有 login_error，不需要带回
  const next = location.pathname === "/" ? "/" : `${location.pathname}${location.search}`;
  const p = providers.data ?? { local: true, oidc: false, oidc_label: "" };
  return (
    <div className="oti-login">
      <div className="oti-ambient" aria-hidden="true">
        <span className="oti-orb oti-orb-a" />
        <span className="oti-orb oti-orb-b" />
        <span className="oti-orb oti-orb-c" />
      </div>

      {/* 左侧：产品说明与「信号示波镜」动效 */}
      <section className="oti-login-hero">
        <div className="oti-login-brand">
          <ScopeEmblem size={30} blips={false} />
          <span>{t("app.title")}</span>
        </div>
        <div className="oti-login-scope">
          <Radar className="oti-radar-login" blips={9} labels={["25", "50", "75", "100"]} />
        </div>
        <div className="oti-login-copy">
          <div className="oti-eyebrow">{t("loginHero.eyebrow")}</div>
          <h1 className="oti-login-headline">{t("loginHero.headline")}</h1>
          <p className="oti-login-sub">{t("loginHero.sub")}</p>
          <ul className="oti-login-features">
            {(["f1", "f2", "f3"] as const).map((k, i) => (
              <li key={k} style={{ ["--i" as string]: i }}>
                <CheckOutlined />
                <span>{t(`loginHero.${k}`)}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* 右侧：登录面板 */}
      <section className="oti-login-panel">
        <div className="oti-login-tools">
          <ThemeSwitch />
          <LanguageSwitch />
        </div>
        <div className="oti-login-card">
          <h2 className="oti-login-title">{t("login.title")}</h2>
          {providers.isPending ? (
            <div style={{ textAlign: "center", padding: "30px 0" }}>
              <Spin />
            </div>
          ) : (
            <Space direction="vertical" style={{ width: "100%" }}>
              {error && (
                <Alert
                  type="error"
                  showIcon
                  closable
                  onClose={() => setParams({})}
                  message={t(LOGIN_ERRORS.has(error) ? `login.error.${error}` : "login.error.generic")}
                />
              )}
              {p.oidc && (
                <Button type="primary" block size="large" href={oidcStartUrl(next)} className="oti-sso-btn">
                  {p.oidc_label ? t("login.sso", { name: p.oidc_label }) : t("login.ssoGeneric")}
                </Button>
              )}
              {p.oidc && p.local && !showLocal && (
                <Button type="link" block onClick={() => setShowLocal(true)}>
                  {t("login.emergency")}
                </Button>
              )}
              {p.local && (!p.oidc || showLocal) && <LocalForm primary={!p.oidc} />}
              {!p.local && !p.oidc && <Alert type="warning" showIcon message={t("login.noMethod")} />}
            </Space>
          )}
        </div>
      </section>
    </div>
  );
}
