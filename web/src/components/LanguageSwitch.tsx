import { Segmented } from "antd";
import { useTranslation } from "react-i18next";
import { saveLang, type Lang } from "../i18n";

export default function LanguageSwitch() {
  const { i18n } = useTranslation();
  return (
    <Segmented
      size="small"
      className="opti-lang-switch"
      value={i18n.language}
      options={[
        { label: "中文", value: "zh-CN" },
        { label: "English", value: "en-US" },
      ]}
      onChange={(v) => {
        const lang = v as Lang;
        saveLang(lang);
        void i18n.changeLanguage(lang);
      }}
    />
  );
}
