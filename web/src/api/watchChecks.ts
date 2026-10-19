import { ApiError, api, unwrap } from "./client";

/** Delivery may have succeeded even when the response was lost. Do not resubmit automatically. */
export class WatchCheckUnconfirmed extends Error {
  constructor() { super("watch check acknowledgement was not received"); }
}

export async function requestWatchCheck(id: number) {
  try {
    const receipt = unwrap(await api.POST("/api/v1/watchlist/{watch_id}/check", { params: { path: { watch_id: id } } }));
    if (receipt?.status !== "queued" || receipt.watch_id !== id || !receipt.request_id) throw new WatchCheckUnconfirmed();
    return receipt;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new WatchCheckUnconfirmed();
  }
}
