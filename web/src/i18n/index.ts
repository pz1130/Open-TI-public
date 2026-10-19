import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import enUS from "./en-US.json";
import zhCN from "./zh-CN.json";

export const LANGS = ["zh-CN", "en-US"] as const;
export type Lang = (typeof LANGS)[number];
const STORAGE_KEY = "opti.lang";

export function initialLang(): Lang {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    if (v === "zh-CN" || v === "en-US") return v;
  } catch {
    // 浏览器禁用存储时使用默认语言
  }
  return "zh-CN";
}

export function saveLang(lang: Lang): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // 忽略
  }
}

void i18n.use(initReactI18next).init({
  resources: { "zh-CN": { translation: zhCN }, "en-US": { translation: enUS } },
  lng: initialLang(),
  fallbackLng: "zh-CN",
  interpolation: { escapeValue: false }, // React 自己转义
});

export default i18n;
