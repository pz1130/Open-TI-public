import { EnterOutlined, SearchOutlined } from "@ant-design/icons";
import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import type { PageDef } from "../pages/registry";
import { groupOf } from "./navGroups";

/**
 * 快速跳转面板（Ctrl/⌘ + K）：只在当前用户有权访问的导航页面里按名称 / 路径过滤。
 * 自绘浮层而不是 Modal，便于做入场动画；Esc、点击遮罩关闭，焦点在打开时进入输入框、关闭时还给触发者。
 */
export default function CommandPalette({ open, pages, onClose, onGo }: { open: boolean; pages: PageDef[]; onClose: () => void; onGo: (p: PageDef) => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const returnTo = useRef<Element | null>(null);

  const items = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return pages;
    return pages.filter((p) => `${t(p.labelKey ?? p.path)} ${p.path} ${t(`shell.group.${groupOf(p)}`)}`.toLowerCase().includes(needle));
  }, [q, pages, t]);

  useEffect(() => {
    if (open) {
      returnTo.current = document.activeElement;
      setQ("");
      setActive(0);
      requestAnimationFrame(() => input.current?.focus());
    } else if (returnTo.current instanceof HTMLElement) {
      returnTo.current.focus();
    }
  }, [open]);

  useEffect(() => setActive(0), [q]);

  if (!open) return null;
  const go = (p: PageDef | undefined) => {
    if (p) onGo(p);
  };
  return createPortal(
    <div className="oti-palette-backdrop" onMouseDown={onClose}>
      <div
        className="oti-palette"
        role="dialog"
        aria-modal="true"
        aria-label={t("shell.palette.title")}
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose();
          } else if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => (items.length ? (a + 1) % items.length : 0));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => (items.length ? (a - 1 + items.length) % items.length : 0));
          } else if (e.key === "Enter") {
            e.preventDefault();
            go(items[active]);
          }
        }}
      >
        <div className="oti-palette-input">
          <SearchOutlined />
          <input
            ref={input}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={t("shell.palette.placeholder")}
            aria-label={t("shell.palette.placeholder")}
            role="combobox"
            aria-expanded="true"
            aria-controls="oti-palette-list"
            aria-activedescendant={items[active] ? `oti-pal-${items[active].path}` : undefined}
          />
          <kbd>Esc</kbd>
        </div>
        <ul className="oti-palette-list" id="oti-palette-list" role="listbox">
          {items.length === 0 && <li className="oti-palette-empty">{t("shell.palette.empty")}</li>}
          {items.map((p, i) => (
            <li
              key={p.path}
              id={`oti-pal-${p.path}`}
              role="option"
              aria-selected={i === active}
              className={i === active ? "oti-palette-item active" : "oti-palette-item"}
              style={{ ["--i" as string]: i }}
              onMouseEnter={() => setActive(i)}
              onClick={() => go(p)}
            >
              <span className="oti-palette-icon">{p.icon}</span>
              <span className="oti-palette-label">{t(p.labelKey ?? p.path)}</span>
              <span className="oti-palette-group">{t(`shell.group.${groupOf(p)}`)}</span>
              <span className="oti-palette-path">/{p.path}</span>
              {i === active && <EnterOutlined className="oti-palette-enter" />}
            </li>
          ))}
        </ul>
        <div className="oti-palette-foot">{t("shell.palette.hint")}</div>
      </div>
    </div>,
    document.body,
  );
}
