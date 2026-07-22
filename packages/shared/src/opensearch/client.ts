import https from 'https';

const OPENSEARCH_API_URL = process.env.OPENSEARCH_API_URL ?? 'http://localhost:9200';
const OPENSEARCH_API_KEY = process.env.OPENSEARCH_API_KEY ?? '';

// Shared https agent that skips self-signed TLS verification in dev
const agent = new https.Agent({ rejectUnauthorized: false });

export async function fetchStats(): Promise<unknown> {
  const resp = await fetch(`${OPENSEARCH_API_URL}/v1/stats`, {
    // @ts-expect-error node fetch agent option
    agent,
    headers: {
      'X-API-Key': OPENSEARCH_API_KEY,
    },
  });
  if (!resp.ok) throw new Error(`Stats fetch failed: ${resp.status}`);
  return resp.json();
}

export async function healthCheck(): Promise<{ status: string; opensearch: string }> {
  const resp = await fetch(`${OPENSEARCH_API_URL}/v1/health`, {
    // @ts-expect-error node fetch agent option
    agent,
  });
  if (!resp.ok) throw new Error(`Health check failed: ${resp.status}`);
  return resp.json() as Promise<{ status: string; opensearch: string }>;
}
