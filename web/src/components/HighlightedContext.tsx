import type { ReactNode } from "react";

/** 在上下文片段中高亮命中词（不区分大小写）。片段来自归一化视图，不对应原文偏移。 */
export default function HighlightedContext({ context, term }: { context: string; term: string }) {
  if (!context) return null;
  const haystack = context.toLowerCase();
  const needle = term.toLowerCase();
  const parts: ReactNode[] = [];
  let from = 0;
  let at = needle ? haystack.indexOf(needle) : -1;
  while (at !== -1) {
    parts.push(context.slice(from, at));
    parts.push(<mark key={at}>{context.slice(at, at + needle.length)}</mark>);
    from = at + needle.length;
    at = haystack.indexOf(needle, from);
  }
  parts.push(context.slice(from));
  return <span className="opti-mono">{parts}</span>;
}
