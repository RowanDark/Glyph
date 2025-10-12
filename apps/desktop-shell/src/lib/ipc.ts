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

const StopRunResponseSchema = z.object({
  id: z.string().optional(),
  status: z.string().optional()
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

const LatencyBucketSchema = z.object({
  upperBoundMs: z.number(),
  count: z.number()
});

const PluginErrorSchema = z.object({
  plugin: z.string(),
  errors: z.number()
});

const DashboardMetricsSchema = z.object({
  failures: z.number(),
  queueDepth: z.number(),
  avgLatencyMs: z.number(),
  casesFound: z.number(),
  eventsTotal: z.number(),
  queueDrops: z.number(),
  latencyBuckets: z.array(LatencyBucketSchema).optional().default([]),
  pluginErrors: z.array(PluginErrorSchema).optional().default([])
});

const CrashFilePreviewSchema = z.object({
  name: z.string(),
  description: z.string(),
  size: z.number().int(),
  sha256: z.string(),
  redacted: z.boolean(),
  snippet: z.string()
});

const CrashPreviewSchema = z.object({
  generatedAt: z.string(),
  files: z.array(CrashFilePreviewSchema),
  warnings: z.array(z.string())
});

const ManifestDnsRecordSchema = z.object({
  host: z.string(),
  addresses: z.array(z.string()).optional().default([])
});

const ManifestTlsRecordSchema = z.object({
  host: z.string(),
  ja3: z.string().optional(),
  ja3Hash: z.string().optional(),
  negotiatedAlpn: z.string().optional(),
  offeredAlpn: z.array(z.string()).optional().default([])
});

const ManifestRobotsRecordSchema = z.object({
  host: z.string(),
  bodyFile: z.string().optional()
});

const ManifestRateLimitSchema = z.object({
  host: z.string(),
  policy: z.string()
});

const ManifestCookieSchema = z.object({
  domain: z.string(),
  name: z.string(),
  value: z.string()
});

const ManifestResponseSchema = z.object({
  requestUrl: z.string(),
  method: z.string(),
  status: z.number().int(),
  headers: z.record(z.array(z.string())).optional().default({}),
  bodyFile: z.string().optional()
});

const ManifestRunnerSchema = z.object({
  glyphctlVersion: z.string().optional(),
  glyphdVersion: z.string().optional(),
  goVersion: z.string().optional(),
  os: z.string().optional(),
  arch: z.string().optional()
});

const ManifestPluginSchema = z.object({
  name: z.string(),
  version: z.string(),
  manifestPath: z.string(),
  signature: z.string(),
  sha256: z.string()
});

const ManifestSchema = z.object({
  version: z.string(),
  createdAt: z.string(),
  seeds: z.record(z.number()).optional().default({}),
  dns: z.array(ManifestDnsRecordSchema).optional().default([]),
  tls: z.array(ManifestTlsRecordSchema).optional().default([]),
  robots: z.array(ManifestRobotsRecordSchema).optional().default([]),
  rateLimits: z.array(ManifestRateLimitSchema).optional().default([]),
  cookies: z.array(ManifestCookieSchema).optional().default([]),
  responses: z.array(ManifestResponseSchema).optional().default([]),
  flowsFile: z.string().optional(),
  runner: ManifestRunnerSchema,
  plugins: z.array(ManifestPluginSchema).optional().default([]),
  findingsFile: z.string(),
  casesFile: z.string(),
  caseTimestamp: z.string()
});

const CaseEvidenceSchema = z.object({
  plugin: z.string(),
  type: z.string(),
  message: z.string(),
  evidence: z.string().optional(),
  metadata: z.record(z.string()).optional().default({})
});

const CaseProofSchema = z.object({
  summary: z.string().optional(),
  steps: z.array(z.string()).optional().default([])
});

const CaseRiskSchema = z.object({
  severity: z.string(),
  score: z.number(),
  rationale: z.string().optional()
});

const CaseSourceSchema = z.object({
  id: z.string(),
  plugin: z.string(),
  type: z.string(),
  severity: z.string(),
  target: z.string().optional()
});

const CaseChainStepSchema = z.object({
  stage: z.number().int(),
  from: z.string(),
  to: z.string(),
  description: z.string(),
  plugin: z.string(),
  type: z.string(),
  findingId: z.string(),
  severity: z.string(),
  weakLink: z.boolean().optional()
});

const CaseGraphSchema = z.object({
  dot: z.string(),
  mermaid: z.string(),
  summary: z.string().optional(),
  attackPath: z.array(CaseChainStepSchema).optional().default([])
});

const CaseSchema = z.object({
  version: z.string(),
  id: z.string(),
  asset: z.object({
    kind: z.string(),
    identifier: z.string(),
    details: z.string().optional()
  }),
  vector: z.object({
    kind: z.string(),
    value: z.string().optional()
  }),
  summary: z.string(),
  evidence: z.array(CaseEvidenceSchema).optional().default([]),
  proof: CaseProofSchema,
  risk: CaseRiskSchema,
  confidence: z.number(),
  confidenceLog: z.string().optional(),
  sources: z.array(CaseSourceSchema).optional().default([]),
  generatedAt: z.string(),
  labels: z.record(z.string()).optional().default({}),
  graph: CaseGraphSchema
});

const OpenArtifactResponseSchema = z.object({
  manifest: ManifestSchema,
  metrics: DashboardMetricsSchema,
  caseCount: z.number().int().nonnegative(),
  flowCount: z.number().int().nonnegative()
});

const ArtifactStatusSchema = z.object({
  loaded: z.boolean(),
  manifest: ManifestSchema.optional(),
  metrics: DashboardMetricsSchema.optional(),
  caseCount: z.number().int().nonnegative(),
  flowCount: z.number().int().nonnegative()
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

const AuditRecordSchema = z
  .object({
    entryId: z.string().optional(),
    signature: z.string().optional(),
    recordedAt: z.string().optional(),
    actor: z.string().optional(),
    action: z.string().optional(),
    decision: z.string().optional()
  })
  .passthrough();

const ResendFlowMetadataSchema = z
  .object({
    parentFlowId: z.string().optional(),
    sourceFlowId: z.string().optional(),
    originalFlowId: z.string().optional(),
    childFlowId: z.string().optional(),
    cloneReason: z.string().optional(),
    audit: z.union([AuditRecordSchema, z.array(AuditRecordSchema)]).optional(),
    auditEntry: AuditRecordSchema.optional(),
    auditTrail: z.array(AuditRecordSchema).optional(),
    clones: z.array(z.string()).optional()
  })
  .passthrough();

const ResendFlowResponseSchema = z.object({
  flowId: z.string(),
  metadata: z.union([ResendFlowMetadataSchema, z.null()]).optional()
});

export type ResendFlowMetadata = z.infer<typeof ResendFlowMetadataSchema> | null | undefined;
export type ResendFlowResponse = z.infer<typeof ResendFlowResponseSchema>;

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
  rationale: z.array(z.string()).optional(),
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
export type LatencyBucket = z.infer<typeof LatencyBucketSchema>;
export type PluginErrorTotal = z.infer<typeof PluginErrorSchema>;
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
export type Manifest = z.infer<typeof ManifestSchema>;
export type CaseRecord = z.infer<typeof CaseSchema>;
export type OpenArtifactResponse = z.infer<typeof OpenArtifactResponseSchema>;
export type ArtifactStatus = z.infer<typeof ArtifactStatusSchema>;
export type CrashFilePreview = z.infer<typeof CrashFilePreviewSchema>;
export type CrashPreview = z.infer<typeof CrashPreviewSchema>;

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

export async function stopRun(id: string) {
  const response = await invoke('stop_run', { id });
  if (!response) {
    return;
  }
  try {
    StopRunResponseSchema.parse(response);
  } catch (error) {
    console.warn('Unexpected stop_run response', error);
  }
}

export async function openArtifact(path: string): Promise<OpenArtifactResponse> {
  const response = await invoke('open_artifact', { path });
  return OpenArtifactResponseSchema.parse(response);
}

export async function getArtifactStatus(): Promise<ArtifactStatus> {
  const status = await invoke('artifact_status');
  return ArtifactStatusSchema.parse(status);
}

export async function fetchArtifactCases(): Promise<CaseRecord[]> {
  const cases = await invoke('list_cases');
  return z.array(CaseSchema).parse(cases);
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
        url.searchParams.set('filters', JSON.stringify(options.filters));
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

export async function prepareCrashReport(): Promise<CrashPreview> {
  const response = await invoke('prepare_crash_report');
  return CrashPreviewSchema.parse(response);
}

export async function saveCrashReport(path: string): Promise<void> {
  await invoke('save_crash_report', { path });
}
