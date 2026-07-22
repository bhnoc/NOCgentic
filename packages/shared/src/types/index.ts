import { z } from 'zod';

export const ChatQuerySchema = z.object({
  query: z.string().min(1).max(5000),
  sessionId: z.string().optional(),
});
export type ChatQuery = z.infer<typeof ChatQuerySchema>;

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
});
export type AgentResponse = z.infer<typeof AgentResponseSchema>;

export interface Alert {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  source: string;
  description: string;
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  action?: string;
}
