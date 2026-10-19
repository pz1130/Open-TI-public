import { Typography } from "antd";

/** 可疑域名只显示为纯文本并可复制，绝不渲染成可点击链接（避免误点进钓鱼站）。 */
export default function DomainText({ value }: { value: string }) {
  return (
    <span onClick={(e) => e.stopPropagation()}>
      <Typography.Text className="opti-mono" copyable={{ text: value }}>
        {value}
      </Typography.Text>
    </span>
  );
}
