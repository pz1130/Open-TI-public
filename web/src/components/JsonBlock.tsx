/** 以纯文本显示 JSON（React 会转义，不解析其中的 HTML）。 */
export default function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="opti-mono" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", fontSize: 12 }}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
