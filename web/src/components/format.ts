import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

dayjs.extend(relativeTime);

/** 服务器给 UTC ISO 时间，按浏览器所在时区显示。 */
export function fmtTime(iso: string | null | undefined): string {
  return iso ? dayjs(iso).format("YYYY-MM-DD HH:mm:ss") : "—";
}

export function fromNow(iso: string | null | undefined): string {
  return iso ? dayjs(iso).fromNow() : "—";
}
