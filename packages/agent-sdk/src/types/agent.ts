export interface AgentTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface AgentCapability {
  name: string;
  description: string;
}

export interface AgentConfig {
  id: string;
  name: string;
  version: string;
  capabilities: AgentCapability[];
  maxConcurrentTasks: number;
  timeoutMs: number;
}

export interface AgentTask {
  taskId: string;
  capability: string;
  input: unknown;
  priority: 'low' | 'medium' | 'high' | 'critical';
  deadline?: Date;
}
