import { z } from 'zod';

export const ChatQuerySchema = z.object({
  query: z.string().min(1).max(5000),
  sessionId: z.string().optional(),
});
export type ChatQuery = z.infer<typeof ChatQuerySchema>;

/**
 * One provider stack's answer to a raced query. Two lanes ship: "cloud" (Gemini)
 * and "local" (AQLight for SQL + Foundation-Sec for prose). Both run the full
 * pipeline concurrently; the first to finish is shown and the UI offers a swap.
 */
export const LaneResultSchema = z.object({
  lane: z.string(),
  label: z.string(),
  answer: z.string(),
  confidence: z.number().min(0).max(1),
  agentUsed: z.string(),
  data: z.unknown().optional(),
  elapsedMs: z.number(),
  winner: z.boolean(),
});
export type LaneResult = z.infer<typeof LaneResultSchema>;

export const AgentResponseSchema = z.object({
  jobId: z.string(),
  status: z.enum(['pending', 'running', 'done', 'error']),
  agentUsed: z.string().optional(),
  answer: z.string().optional(),
  confidence: z.number().min(0).max(1).optional(),
  data: z.unknown().optional(),
  hints: z.array(z.string()).optional(),
  error: z.string().optional(),
  createdAt: z.string(),
  completedAt: z.string().optional(),
  // Lane race metadata. `lane` names the stack that produced `answer`; `lanes`
  // holds every lane that has landed. `lanesRacing` is true while the losing
  // lane is still in flight, which is the client's cue to keep polling.
  lane: z.string().optional(),
  lanes: z.array(LaneResultSchema).optional(),
  lanesRacing: z.boolean().optional(),
});
export type AgentResponse = z.infer<typeof AgentResponseSchema>;

export interface Alert {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
  source: string;
  description: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  uid?: string;
  network?: string;
  /** Original Athena event time; `timestamp` is re-stamped on emit for the feed clock. */
  observedAt?: string;
  occurrences?: number;
  action?: string;
}
