import "@ant-design/v5-patch-for-react-19";
// 字体随前端打包为同源文件：CSP 只允许 font-src 'self'，且不向第三方暴露访问者。
// 等宽字体用来显示域名，保留全部子集（西里尔、希腊等同形字常见于仿冒域名）；标题字体只要拉丁字符。
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/700.css";
import "@fontsource/rajdhani/latin-500.css";
import "@fontsource/rajdhani/latin-ext-500.css";
import "@fontsource/rajdhani/latin-600.css";
import "@fontsource/rajdhani/latin-ext-600.css";
import "@fontsource/rajdhani/latin-700.css";
import "@fontsource/rajdhani/latin-ext-700.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./i18n";
import "./index.css";

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
