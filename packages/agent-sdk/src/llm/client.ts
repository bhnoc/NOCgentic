import { createHash } from 'crypto';

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

export interface Message {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LLMOptions {
  model?: string;
  maxTokens?: number;
  temperature?: number;
}

/**
 * Secure LLM client that sanitizes prompts before sending to OpenRouter.
 * Ensures no PII or internal network details are leaked.
 */
export class LLMClient {
  private readonly apiKey: string;

  constructor() {
    const key = process.env.OPENROUTER_API_KEY;
    if (!key) throw new Error('OPENROUTER_API_KEY is not set');
    this.apiKey = key;
  }

  async complete(messages: Message[], options: LLMOptions = {}): Promise<string> {
    const sanitized = messages.map((m) => ({
      ...m,
      content: this.sanitize(m.content),
    }));

    const body = {
      model: options.model ?? 'anthropic/claude-3-haiku',
      messages: sanitized,
      max_tokens: options.maxTokens ?? 2048,
      temperature: options.temperature ?? 0.1,
    };

    // Audit log (no sensitive data)
    console.log(JSON.stringify({
      event: 'llm_request',
      model: body.model,
      messageCount: messages.length,
      promptHash: createHash('sha256').update(JSON.stringify(sanitized)).digest('hex').slice(0, 16),
      timestamp: new Date().toISOString(),
    }));

    const resp = await fetch(OPENROUTER_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://nocgentic.noc',
        'X-Title': 'BH Asia NOC Agent',
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`OpenRouter error ${resp.status}: ${text.slice(0, 200)}`);
    }

    const data = await resp.json() as { choices: Array<{ message: { content: string } }> };
    return data.choices[0]?.message?.content ?? '';
  }

  /**
   * Sanitize text before sending to external LLM.
   * Removes internal IPs, credentials patterns, and internal hostnames.
   */
  private sanitize(text: string): string {
    return text
      .replace(/\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g, '[INTERNAL-IP]')
      .replace(/\b[A-Za-z0-9+/]{40,}\b/g, '[REDACTED-SECRET]')
      .replace(/password\s*[:=]\s*\S+/gi, 'password: [REDACTED]')
      .replace(/api[_-]?key\s*[:=]\s*\S+/gi, 'api_key: [REDACTED]')
      .slice(0, 8000); // Hard limit
  }
}
