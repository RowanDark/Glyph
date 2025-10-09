import { invoke } from '@tauri-apps/api/tauri';
import { listen, type Event } from '@tauri-apps/api/event';
import { z } from 'zod';

const RunSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string(),
  createdAt: z.preprocess((value) => {
    if (typeof value === 'number') {
      return new Date(value * 1000).toISOString();
    }
    return value;
  }, z.string())
});

const StartRunResponseSchema = z.object({
  id: z.string()
});

export type StartRunPayload = {
  name: string;
  template?: string;
  targets: string[];
  targetNotes?: string;
  scopePolicy: string;
  plugins: string[];
  limits: {
    concurrency: number;
    maxRps: number;
    maxFindings: number;
    safeMode: boolean;
  };
  auth: {
    strategy: string;
    apiKey?: string;
    username?: string;
    password?: string;
    oauthClientId?: string;
    oauthClientSecret?: string;
  };
  schedule: {
    mode: 'now' | 'later';
    startAt?: string;
    timezone?: string;
  };
};

const DashboardMetricsSchema = z.object({
  failures: z.number(),
  queueDepth: z.number(),
  avgLatencyMs: z.number(),
  casesFound: z.number()
});

const timestampSchema = z.preprocess((value) => {
  if (typeof value === 'number') {
    return new Date(value * 1000).toISOString();
  }
  return value;
}, z.string());

const FlowEventSchema = z.object({
  id: z.string(),
  sequence: z.number().int(),
  timestamp: timestampSchema,
  type: z.string(),
  sanitized: z.string().optional(),
  sanitizedBase64: z.string().optional(),
  raw: z.string().optional(),
  rawBase64: z.string().optional(),
  rawBodySize: z.number().int().optional(),
  rawBodyCaptured: z.number().int().optional(),
  sanitizedRedacted: z.boolean().optional(),
  scope: z.string().optional(),
  tags: z.array(z.string()).optional(),
  pluginTags: z.array(z.string()).optional(),
  metadata: z.unknown().optional()
});

const FlowPageSchema = z.object({
  items: z.array(FlowEventSchema),
  nextCursor: z.string().optional().nullable()
});

const ResendFlowResponseSchema = z.object({
  flowId: z.string(),
  metadata: z.unknown().optional()
});

const ScopeRuleSchema = z.object({
  type: z.string(),
  value: z.string(),
  notes: z.string().optional()
});

const ScopePolicyDocumentSchema = z.object({
  policy: z.string(),
  source: z.string().optional(),
  updatedAt: z.string().optional()
});

const ScopeValidationMessageSchema = z.object({
  message: z.string(),
  line: z.number().int().optional(),
  column: z.number().int().optional(),
  path: z.string().optional()
});

const ScopeValidationResultSchema = z.object({
  valid: z.boolean(),
  errors: z.array(ScopeValidationMessageSchema),
  warnings: z.array(ScopeValidationMessageSchema).optional().default([])
});

const ScopeApplyResponseSchema = z.object({
  policy: z.string(),
  appliedAt: z.string(),
  warnings: z.array(ScopeValidationMessageSchema).optional().default([])
});

const ScopeParseSuggestionSchema = z.object({
  policy: z.string(),
  summary: z.string().optional(),
  notes: z.string().optional(),
  rules: z
    .object({
      allow: z.array(ScopeRuleSchema).optional().default([]),
      deny: z.array(ScopeRuleSchema).optional().default([])
    })
    .optional()
});

const ScopeParseResponseSchema = z.object({
  suggestions: z.array(ScopeParseSuggestionSchema)
});

const ScopeDryRunDecisionSchema = z.object({
  url: z.string(),
  allowed: z.boolean(),
  reason: z.string().optional(),
  matchedRule: ScopeRuleSchema.optional()
});

const ScopeDryRunResponseSchema = z.object({
  results: z.array(ScopeDryRunDecisionSchema)
});

export type Run = z.infer<typeof RunSchema>;
export type DashboardMetrics = z.infer<typeof DashboardMetricsSchema>;
export type FlowEvent = z.infer<typeof FlowEventSchema>;
export type FlowPage = z.infer<typeof FlowPageSchema>;
export type ScopePolicyDocument = z.infer<typeof ScopePolicyDocumentSchema>;
export type ScopeValidationMessage = z.infer<typeof ScopeValidationMessageSchema>;
export type ScopeValidationResult = z.infer<typeof ScopeValidationResultSchema>;
export type ScopeApplyResponse = z.infer<typeof ScopeApplyResponseSchema>;
export type ScopeParseSuggestion = z.infer<typeof ScopeParseSuggestionSchema>;
export type ScopeParseResponse = z.infer<typeof ScopeParseResponseSchema>;
export type ScopeDryRunDecision = z.infer<typeof ScopeDryRunDecisionSchema>;
export type ScopeDryRunResponse = z.infer<typeof ScopeDryRunResponseSchema>;

export type FlowFilters = {
  search?: string;
  methods?: string[];
  statuses?: number[];
  domains?: string[];
  scope?: string[];
  tags?: string[];
  pluginTags?: string[];
};

export type RunEvent = {
  type: string;
  timestamp: string;
  payload?: unknown;
};

export type StreamHandle = {
  close: () => Promise<void>;
};

export type FlowStreamHandle = {
  close: () => Promise<void>;
};

export async function listRuns(): Promise<Run[]> {
  const runs = await invoke('list_runs');
  return z.array(RunSchema).parse(runs);
}

export async function startRun(payload: StartRunPayload) {
  const response = await invoke('start_run', { payload });
  return StartRunResponseSchema.parse(response);
}

export async function fetchMetrics(): Promise<DashboardMetrics> {
  const metrics = await invoke('fetch_metrics');
  return DashboardMetricsSchema.parse(metrics);
}

export async function listFlows(payload: {
  cursor?: string;
  limit?: number;
  filters?: FlowFilters;
} = {}): Promise<FlowPage> {
  const response = await invoke('list_flows', payload);
  return FlowPageSchema.parse(response);
}

export async function streamEvents(runId: string, onEvent: (event: RunEvent) => void) {
  const eventName = `runs:${runId}:events`;
  const unlisten = await listen(eventName, (event: Event<RunEvent>) => {
    if (event.payload) {
      onEvent(event.payload);
    }
  });

  await invoke('stream_events', { run_id: runId });

  return {
    close: async () => {
      await invoke('stop_stream', { run_id: runId });
      unlisten();
    }
  } satisfies StreamHandle;
}

export async function streamFlowEvents(
  streamId: string,
  onEvent: (event: FlowEvent) => void,
  options: { filters?: FlowFilters } = {}
): Promise<FlowStreamHandle> {
  const isTauri =
    typeof window !== 'undefined' &&
    Boolean((window as typeof window & { __TAURI_IPC__?: unknown }).__TAURI_IPC__);

  if (typeof window !== 'undefined' && !isTauri) {
    try {
      const base = import.meta.env.VITE_API_BASE_URL ?? window.location.origin;
      const url = new URL('/api/flows/stream', base);
      url.searchParams.set('streamId', streamId);
      if (options.filters) {
        url.searchParams.set('filters', encodeURIComponent(JSON.stringify(options.filters)));
      }

      const eventSource = new EventSource(url.toString(), { withCredentials: true });

      const handleMessage = (event: MessageEvent<string>) => {
        if (!event.data) {
          return;
        }
        try {
          const parsed = FlowEventSchema.parse(JSON.parse(event.data));
          onEvent(parsed);
        } catch (error) {
          console.warn('Failed to parse flow event payload from SSE', error);
        }
      };

      eventSource.addEventListener('message', handleMessage);
      eventSource.addEventListener('error', (error) => {
        console.warn('Flow SSE stream error', error);
      });

      return {
        close: async () => {
          eventSource.removeEventListener('message', handleMessage);
          eventSource.close();
        }
      } satisfies FlowStreamHandle;
    } catch (error) {
      console.warn('Falling back to native flow stream', error);
    }
  }

  const eventName = `flows:${streamId}:events`;
  const unlisten = await listen(eventName, (event: Event<unknown>) => {
    if (!event.payload) {
      return;
    }
    try {
      const parsed = FlowEventSchema.parse(event.payload);
      onEvent(parsed);
    } catch (error) {
      console.warn('Failed to parse flow event payload', error);
    }
  });

  await invoke('stream_flows', { stream_id: streamId, filters: options.filters });

  return {
    close: async () => {
      await invoke('stop_flow_stream', { stream_id: streamId });
      unlisten();
    }
  } satisfies FlowStreamHandle;
}

export async function resendFlow(flowId: string, message: string) {
  const response = await invoke('resend_flow', { flow_id: flowId, message });
  return ResendFlowResponseSchema.parse(response);
}

export async function fetchScopePolicy(): Promise<ScopePolicyDocument> {
  const response = await invoke('fetch_scope_policy');
  return ScopePolicyDocumentSchema.parse(response);
}

export async function validateScopePolicy(policy: string): Promise<ScopeValidationResult> {
  const response = await invoke('validate_scope_policy', { policy });
  return ScopeValidationResultSchema.parse(response);
}

export async function applyScopePolicy(policy: string): Promise<ScopeApplyResponse> {
  const response = await invoke('apply_scope_policy', { policy });
  return ScopeApplyResponseSchema.parse(response);
}

export async function parseScopeText(text: string): Promise<ScopeParseResponse> {
  const response = await invoke('parse_scope_text', { text });
  return ScopeParseResponseSchema.parse(response);
}

export async function dryRunScopePolicy(payload: {
  policy?: string;
  urls: string[];
}): Promise<ScopeDryRunResponse> {
  const response = await invoke('dry_run_scope_policy', payload);
  return ScopeDryRunResponseSchema.parse(response);
}
