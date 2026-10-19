import { Segmented } from "antd";
import { MoonOutlined, SunOutlined } from "@ant-design/icons";
import { useTranslation } from "react-i18next";
import { useTheme } from "../theme";

export default function ThemeSwitch() {
  const { t } = useTranslation();
  const { theme, setTheme } = useTheme();
  return (
    <Segmented
      size="small"
      value={theme}
      options={[
        { value: "dark", icon: <MoonOutlined aria-label={t("app.themeDark")} /> },
        { value: "light", icon: <SunOutlined aria-label={t("app.themeLight")} /> },
      ]}
      onChange={(v) => setTheme(v as "dark" | "light")}
      className="opti-theme-switch"
    />
  );
}
