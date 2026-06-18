import { logger } from "./logger";

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

/**
 * LLM abstraction layer — currently backed by OpenAI.
 * Returns null (caller falls back to templates) when OPENAI_API_KEY is absent.
 * Swap the implementation here to change providers platform-wide.
 */
export async function llmComplete(
  messages: LLMMessage[],
  { maxTokens = 1500, model = "gpt-4o-mini" }: { maxTokens?: number; model?: string } = {},
): Promise<string | null> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    logger.warn("OPENAI_API_KEY not set — AI copilot using structured-template fallback");
    return null;
  }

  try {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        messages,
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      logger.error({ status: res.status, body }, "OpenAI API error");
      return null;
    }

    const data = (await res.json()) as any;
    return (data.choices?.[0]?.message?.content as string) ?? null;
  } catch (err) {
    logger.error({ err }, "OpenAI fetch failed");
    return null;
  }
}

/** True when the LLM is available at runtime. */
export function isLLMAvailable(): boolean {
  return !!process.env.OPENAI_API_KEY;
}
