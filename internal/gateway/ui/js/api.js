/**
 * Fetch wrapper — throws on non-2xx with a human-readable error message.
 */
export async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const msg = data && typeof data === "object" && data.error ? data.error : `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data;
}
