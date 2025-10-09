import { createFileRoute } from '@tanstack/react-router';
import { useVirtualizer } from '@tanstack/react-virtual';
import {
  AlertTriangle,
  Filter,
  RefreshCw,
  Search,
  Send,
  Shield,
  Timer
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState, useTransition } from 'react';
import { toast } from 'sonner';

import { Button } from '../components/ui/button';
import {
  FlowEvent,
  FlowStreamHandle,
  listFlows,
  resendFlow,
  streamFlowEvents
} from '../lib/ipc';
import { cn } from '../lib/utils';

type HttpHeader = {
  name: string;
  value: string;
};

type ParsedHttpMessage = {
  startLine: string;
  headers: HttpHeader[];
  body: string;
  prettyBody?: string;
  format: 'json' | 'form' | 'text';
  contentType?: string;
  isBinary: boolean;
  isTruncated: boolean;
  size: number;
};

type FlowMessage = {
  timestamp: string;
  raw: string;
  parsed: ParsedHttpMessage | null;
  sanitizedRedacted?: boolean;
  rawBodySize?: number;
  rawBodyCaptured?: number;
};

type FlowEntry = {
  id: string;
  flowId: string;
  method?: string;
  path?: string;
  host?: string;
  url?: string;
  domain?: string;
  statusCode?: number;
  statusText?: string;
  tags: string[];
  pluginTags: string[];
  scope: string;
  updatedAt: string;
  request?: FlowMessage;
  response?: FlowMessage;
  requestSize?: number;
  responseSize?: number;
  requestBinary?: boolean;
  responseBinary?: boolean;
  requestTruncated?: boolean;
  responseTruncated?: boolean;
  requestRedacted?: boolean;
  responseRedacted?: boolean;
  durationMs?: number;
  searchText: string;
};

type DiffChunk = {
  type: 'equal' | 'add' | 'remove';
  value: string;
};

const ITEM_HEIGHT = 136;
const STREAM_ID = 'timeline';
const LARGE_BODY_THRESHOLD = 64 * 1024;

function decodeBase64(value: string | undefined | null): string {
  if (!value) {
    return '';
  }
  try {
    if (typeof globalThis.atob === 'function') {
      return globalThis.atob(value);
    }
  } catch {
    return value;
  }
  return value;
}

function normaliseScope(raw?: string | null): string {
  if (!raw) {
    return 'in-scope';
  }
  const value = raw.toLowerCase();
  if (value.includes('out')) {
    return 'out-of-scope';
  }
  return 'in-scope';
}

function parseHttpMessage(raw: string): ParsedHttpMessage | null {
  if (!raw) {
    return null;
  }
  const normalised = raw.replace(/\r\n/g, '\n');
  const lines = normalised.split('\n');
  if (lines.length === 0) {
    return null;
  }
  const startLine = lines[0] ?? '';
  let separatorIndex = lines.indexOf('');
  if (separatorIndex === -1) {
    separatorIndex = lines.length;
  }
  const headerLines = lines.slice(1, separatorIndex);
  const bodyLines = lines.slice(separatorIndex + 1);
  const headers: HttpHeader[] = headerLines
    .map((line) => {
      const [name, ...rest] = line.split(':');
      const value = rest.join(':').trim();
      const trimmedName = name.trim();
      if (!trimmedName) {
        return null;
      }
      return { name: trimmedName, value };
    })
    .filter((header): header is HttpHeader => Boolean(header));
  const body = bodyLines.join('\n');
  const isBinary = /[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(body);
  const contentLengthHeader = headers.find(
    (header) => header.name.toLowerCase() === 'content-length'
  );
  const size = (() => {
    if (!contentLengthHeader) {
      return body.length;
    }
    const parsed = Number.parseInt(contentLengthHeader.value, 10);
    if (Number.isNaN(parsed) || parsed < 0) {
      return body.length;
    }
    return parsed;
  })();
  const contentType = headers.find(
    (header) => header.name.toLowerCase() === 'content-type'
  )?.value;
  const isTruncated = headers.some((header) => {
    const key = header.name.toLowerCase();
    return (
      key === 'x-glyph-body-redacted' ||
      key === 'x-glyph-raw-body-truncated' ||
      key === 'x-glyph-body-truncated'
    );
  });

  let prettyBody: string | undefined;
  let format: ParsedHttpMessage['format'] = 'text';

  if (!isBinary && body.trim()) {
    const lowerType = contentType?.toLowerCase() ?? '';
    if (lowerType.includes('json')) {
      try {
        prettyBody = JSON.stringify(JSON.parse(body), null, 2);
        format = 'json';
      } catch {
        prettyBody = undefined;
      }
    } else if (lowerType.includes('x-www-form-urlencoded')) {
      try {
        const params = new URLSearchParams(body);
        const entries: string[] = [];
        params.forEach((value, key) => {
          entries.push(`${key}=${value}`);
        });
        prettyBody = entries.join('\n');
        format = 'form';
      } catch {
        prettyBody = undefined;
      }
    }
  }

  return {
    startLine,
    headers,
    body,
    prettyBody,
    format,
    contentType,
    isBinary,
    isTruncated,
    size
  };
}

function extractRequestSummary(startLine: string, headers: HttpHeader[]) {
  const parts = startLine.trim().split(/\s+/);
  const method = parts[0]?.toUpperCase();
  let target = parts[1] ?? '';
  let host = headers.find((header) => header.name.toLowerCase() === 'host')?.value;

  if (target.startsWith('http://') || target.startsWith('https://')) {
    try {
      const url = new URL(target);
      host = url.host;
      target = url.pathname + url.search;
    } catch {
      // ignore parsing errors
    }
  } else if (target && !target.startsWith('/')) {
    target = `/${target}`;
  }

  const url = host ? `https://${host}${target || ''}` : undefined;

  return {
    method,
    path: target || undefined,
    host: host || undefined,
    url
  };
}

function extractResponseSummary(startLine: string) {
  const match = startLine.match(/^\S+\s+(\d{3})(?:\s+(.*))?$/);
  if (!match) {
    return { statusCode: undefined, statusText: undefined };
  }
  const statusCode = Number.parseInt(match[1], 10);
  const statusText = match[2]?.trim();
  return {
    statusCode: Number.isNaN(statusCode) ? undefined : statusCode,
    statusText: statusText && statusText.length > 0 ? statusText : undefined
  };
}

function computeDuration(start?: string, end?: string): number | undefined {
  if (!start || !end) {
    return undefined;
  }
  const startMs = new Date(start).getTime();
  const endMs = new Date(end).getTime();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
    return undefined;
  }
  return Math.max(0, endMs - startMs);
}

function formatDuration(durationMs?: number) {
  if (!Number.isFinite(durationMs)) {
    return '—';
  }
  if (!durationMs || durationMs < 1) {
    return '<1 ms';
  }
  if (durationMs < 1000) {
    return `${Math.round(durationMs)} ms`;
  }
  if (durationMs < 60_000) {
    return `${(durationMs / 1000).toFixed(1)} s`;
  }
  return `${Math.round(durationMs / 1000)} s`;
}

function formatBytes(size?: number) {
  if (!Number.isFinite(size) || size === undefined) {
    return '—';
  }
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = size;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const display =
    value >= 10 || Math.abs(value - Math.round(value)) < 0.05
      ? Math.round(value).toString()
      : value.toFixed(1);
  return `${display} ${units[unitIndex]}`;
}

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) {
    return '—';
  }
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

function buildSearchIndex(entry: FlowEntry): string {
  const parts: string[] = [];
  if (entry.method) {
    parts.push(entry.method);
  }
  if (entry.host) {
    parts.push(entry.host);
  }
  if (entry.path) {
    parts.push(entry.path);
  }
  if (entry.statusCode) {
    parts.push(entry.statusCode.toString());
  }
  if (entry.statusText) {
    parts.push(entry.statusText);
  }
  if (entry.tags.length > 0) {
    parts.push(entry.tags.join(' '));
  }
  if (entry.pluginTags.length > 0) {
    parts.push(entry.pluginTags.join(' '));
  }
  if (entry.request?.parsed?.body) {
    parts.push(entry.request.parsed.body);
  }
  if (entry.response?.parsed?.body) {
    parts.push(entry.response.parsed.body);
  }
  return parts.join(' ').toLowerCase();
}

function getMethodTone(method?: string) {
  switch ((method ?? '').toUpperCase()) {
    case 'GET':
      return 'bg-blue-500/10 text-blue-500';
    case 'POST':
      return 'bg-emerald-500/10 text-emerald-500';
    case 'PUT':
      return 'bg-amber-500/10 text-amber-500';
    case 'DELETE':
      return 'bg-red-500/10 text-red-500';
    case 'PATCH':
      return 'bg-purple-500/10 text-purple-500';
    default:
      return 'bg-muted text-muted-foreground';
  }
}

function getStatusTone(status?: number) {
  if (status === undefined) {
    return 'bg-muted text-muted-foreground';
  }
  if (status >= 500) {
    return 'bg-red-500/10 text-red-500';
  }
  if (status >= 400) {
    return 'bg-amber-500/10 text-amber-500';
  }
  if (status >= 300) {
    return 'bg-blue-500/10 text-blue-500';
  }
  if (status >= 200) {
    return 'bg-emerald-500/10 text-emerald-500';
  }
  return 'bg-muted text-muted-foreground';
}

function computeDiff(original: string, updated: string): DiffChunk[] {
  const originalLines = original.split(/\r?\n/);
  const updatedLines = updated.split(/\r?\n/);
  const m = originalLines.length;
  const n = updatedLines.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = m - 1; i >= 0; i -= 1) {
    for (let j = n - 1; j >= 0; j -= 1) {
      if (originalLines[i] === updatedLines[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const result: DiffChunk[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (originalLines[i] === updatedLines[j]) {
      result.push({ type: 'equal', value: originalLines[i] });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      result.push({ type: 'remove', value: originalLines[i] });
      i += 1;
    } else {
      result.push({ type: 'add', value: updatedLines[j] });
      j += 1;
    }
  }
  while (i < m) {
    result.push({ type: 'remove', value: originalLines[i] });
    i += 1;
  }
  while (j < n) {
    result.push({ type: 'add', value: updatedLines[j] });
    j += 1;
  }
  return result;
}

function integrateFlowEvent(existing: FlowEntry | undefined, event: FlowEvent): FlowEntry {
  const baseId = event.id.replace(/:(request|response)$/i, '');
  const normalizedType = event.type.toUpperCase();
  const direction: 'request' | 'response' | 'unknown' = normalizedType.includes('REQUEST')
    ? 'request'
    : normalizedType.includes('RESPONSE')
      ? 'response'
      : 'unknown';

  const sanitized = event.sanitized ?? decodeBase64(event.sanitizedBase64);
  const raw = event.raw ?? decodeBase64(event.rawBase64);
  const messageText = sanitized || raw || '';
  const parsed = parseHttpMessage(messageText);

  const entry: FlowEntry = existing
    ? {
        ...existing,
        tags: [...existing.tags],
        pluginTags: [...existing.pluginTags],
        request: existing.request
          ? { ...existing.request, parsed: existing.request.parsed }
          : undefined,
        response: existing.response
          ? { ...existing.response, parsed: existing.response.parsed }
          : undefined
      }
    : {
        id: baseId,
        flowId: baseId,
        tags: [],
        pluginTags: [],
        scope: 'in-scope',
        updatedAt: event.timestamp,
        searchText: ''
      };

  const normalisedScope = normaliseScope(event.scope);
  entry.scope = normalisedScope;
  entry.updatedAt = event.timestamp;

  const tagSet = new Set(entry.tags);
  for (const tag of event.tags ?? []) {
    const trimmed = tag.trim();
    if (trimmed) {
      tagSet.add(trimmed);
    }
  }
  entry.tags = Array.from(tagSet).sort();

  const pluginTagSet = new Set(entry.pluginTags);
  for (const tag of event.pluginTags ?? []) {
    const trimmed = tag.trim();
    if (trimmed) {
      pluginTagSet.add(trimmed);
    }
  }
  entry.pluginTags = Array.from(pluginTagSet).sort();

  if (direction === 'request') {
    const summary = parsed ? extractRequestSummary(parsed.startLine, parsed.headers) : undefined;
    entry.method = summary?.method ?? entry.method;
    entry.path = summary?.path ?? entry.path;
    entry.host = summary?.host ?? entry.host;
    entry.url = summary?.url ?? entry.url;
    entry.domain = entry.host ? entry.host.toLowerCase().replace(/:\d+$/, '') : entry.domain;
    const rawBodySize = event.rawBodySize ?? entry.request?.rawBodySize;
    const rawBodyCaptured = event.rawBodyCaptured ?? entry.request?.rawBodyCaptured;
    const rawTruncated =
      typeof rawBodySize === 'number' &&
      typeof rawBodyCaptured === 'number' &&
      rawBodyCaptured >= 0 &&
      rawBodyCaptured < rawBodySize;

    entry.request = {
      timestamp: event.timestamp,
      raw: messageText,
      parsed,
      sanitizedRedacted: event.sanitizedRedacted ?? entry.request?.sanitizedRedacted,
      rawBodySize,
      rawBodyCaptured
    };
    entry.requestSize = parsed?.size ?? rawBodySize ?? entry.requestSize;
    entry.requestBinary = parsed?.isBinary ?? entry.requestBinary;
    entry.requestTruncated = Boolean(parsed?.isTruncated || rawTruncated);
    entry.requestRedacted = event.sanitizedRedacted ?? entry.requestRedacted;
  } else if (direction === 'response') {
    const summary = parsed ? extractResponseSummary(parsed.startLine) : undefined;
    entry.statusCode = summary?.statusCode ?? entry.statusCode;
    entry.statusText = summary?.statusText ?? entry.statusText;
    const rawBodySize = event.rawBodySize ?? entry.response?.rawBodySize;
    const rawBodyCaptured = event.rawBodyCaptured ?? entry.response?.rawBodyCaptured;
    const rawTruncated =
      typeof rawBodySize === 'number' &&
      typeof rawBodyCaptured === 'number' &&
      rawBodyCaptured >= 0 &&
      rawBodyCaptured < rawBodySize;

    entry.response = {
      timestamp: event.timestamp,
      raw: messageText,
      parsed,
      sanitizedRedacted: event.sanitizedRedacted ?? entry.response?.sanitizedRedacted,
      rawBodySize,
      rawBodyCaptured
    };
    entry.responseSize = parsed?.size ?? rawBodySize ?? entry.responseSize;
    entry.responseBinary = parsed?.isBinary ?? entry.responseBinary;
    entry.responseTruncated = Boolean(parsed?.isTruncated || rawTruncated);
    entry.responseRedacted = event.sanitizedRedacted ?? entry.responseRedacted;
  }

  entry.durationMs = computeDuration(entry.request?.timestamp, entry.response?.timestamp);
  entry.searchText = buildSearchIndex(entry);

  return entry;
}

function FlowListItem({
  flow,
  selected,
  onSelect
}: {
  flow: FlowEntry;
  selected: boolean;
  onSelect: () => void;
}) {
  const methodTone = getMethodTone(flow.method);
  const statusTone = getStatusTone(flow.statusCode);
  const statusLabel = flow.statusCode
    ? `${flow.statusCode}${flow.statusText ? ` ${flow.statusText}` : ''}`
    : 'Pending';
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'flex w-full flex-col justify-between rounded-lg border p-3 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2',
        selected
          ? 'border-primary bg-primary/10 shadow'
          : 'border-transparent hover:border-border hover:bg-muted/40'
      )}
      style={{ height: ITEM_HEIGHT - 12 }}
    >
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{formatTimestamp(flow.updatedAt)}</span>
        <span className="flex items-center gap-1">
          <Timer className="h-3 w-3" />
          {formatDuration(flow.durationMs)}
        </span>
      </div>
      <div className="mt-2 flex items-center gap-2">
        <span
          className={cn(
            'rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wide',
            methodTone
          )}
        >
          {flow.method ?? '—'}
        </span>
        <span className="truncate text-sm font-medium text-foreground">
          {flow.path ?? flow.url ?? flow.id}
        </span>
      </div>
      <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
        <span className="truncate">{flow.host ?? 'Unknown host'}</span>
        <span
          className={cn(
            'rounded-full px-2 py-0.5 text-xs font-semibold uppercase',
            statusTone
          )}
        >
          {statusLabel}
        </span>
      </div>
      <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
        <div className="flex items-center gap-3">
          <span>Req {formatBytes(flow.requestSize)}</span>
          <span>Res {formatBytes(flow.responseSize)}</span>
        </div>
        <div className="flex items-center gap-3">
          {(flow.requestTruncated || flow.responseTruncated) && (
            <span className="flex items-center gap-1 text-amber-500">
              <AlertTriangle className="h-3 w-3" /> Truncated
            </span>
          )}
          {(flow.requestRedacted || flow.responseRedacted) && (
            <span className="flex items-center gap-1 text-sky-500">
              <Shield className="h-3 w-3" /> Redacted
            </span>
          )}
        </div>
      </div>
    </button>
  );
}

function HttpMessageViewer({ message }: { message?: FlowMessage }) {
  const [mode, setMode] = useState<'pretty' | 'raw'>('pretty');
  const parsed = message?.parsed ?? null;
  const prettyAvailable = Boolean(parsed?.prettyBody && parsed.prettyBody !== parsed.body);

  useEffect(() => {
    if (prettyAvailable) {
      setMode('pretty');
    } else {
      setMode('raw');
    }
  }, [message?.raw, prettyAvailable]);

  if (!message) {
    return (
      <div className="mt-3 rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
        Awaiting message…
      </div>
    );
  }

  const activeMode = mode === 'pretty' && prettyAvailable ? 'pretty' : 'raw';
  const body =
    activeMode === 'pretty'
      ? parsed?.prettyBody ?? parsed?.body ?? message.raw
      : parsed?.body ?? message.raw;

  return (
    <div className="mt-3 space-y-3 rounded-md border border-border bg-card p-4">
      {parsed ? (
        <div className="space-y-2">
          <div className="font-mono text-sm text-primary">{parsed.startLine}</div>
          <div className="space-y-1 text-xs text-muted-foreground">
            {parsed.headers.map((header) => (
              <div key={`${header.name}:${header.value}`} className="flex gap-2">
                <span className="font-semibold text-foreground">{header.name}:</span>
                <span>{header.value}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="text-sm text-muted-foreground">Message metadata unavailable.</div>
      )}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => setMode('pretty')}
          className={cn(
            'rounded-md px-2 py-1 text-xs font-medium transition',
            activeMode === 'pretty'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted text-muted-foreground hover:bg-muted/80',
            !prettyAvailable && 'opacity-60'
          )}
          disabled={!prettyAvailable}
        >
          Pretty
        </button>
        <button
          type="button"
          onClick={() => setMode('raw')}
          className={cn(
            'rounded-md px-2 py-1 text-xs font-medium transition',
            activeMode === 'raw'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted text-muted-foreground hover:bg-muted/80'
          )}
        >
          Raw
        </button>
      </div>
      <pre className="max-h-80 overflow-auto rounded bg-muted px-3 py-2 text-xs font-mono leading-relaxed text-foreground">
        {body || '∅'}
      </pre>
    </div>
  );
}

function FilterGroup({
  title,
  options,
  selected,
  onToggle,
  emptyLabel
}: {
  title: string;
  options: string[];
  selected: string[];
  onToggle: (value: string) => void;
  emptyLabel?: string;
}) {
  if (options.length === 0) {
    return null;
  }
  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase text-muted-foreground">{title}</span>
        {selected.length > 0 && (
          <span className="text-xs text-primary">{selected.length}</span>
        )}
      </div>
      <div className="mt-2 space-y-1">
        {options.map((option) => {
          const id = `${title}-${option}`;
          const checked = selected.includes(option);
          return (
            <label
              key={option}
              htmlFor={id}
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-muted/40"
            >
              <input
                id={id}
                type="checkbox"
                className="h-3 w-3 rounded border-border text-primary focus-visible:outline-none focus-visible:ring-0"
                checked={checked}
                onChange={() => onToggle(option)}
              />
              <span className="truncate">{option || emptyLabel || 'Unknown'}</span>
            </label>
          );
        })}
      </div>
    </div>
  );
}

function NumberFilterGroup({
  title,
  options,
  selected,
  onToggle
}: {
  title: string;
  options: number[];
  selected: number[];
  onToggle: (value: number) => void;
}) {
  if (options.length === 0) {
    return null;
  }
  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase text-muted-foreground">{title}</span>
        {selected.length > 0 && (
          <span className="text-xs text-primary">{selected.length}</span>
        )}
      </div>
      <div className="mt-2 space-y-1">
        {options.map((option) => {
          const id = `${title}-${option}`;
          const checked = selected.includes(option);
          return (
            <label
              key={option}
              htmlFor={id}
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-muted/40"
            >
              <input
                id={id}
                type="checkbox"
                className="h-3 w-3 rounded border-border text-primary focus-visible:outline-none focus-visible:ring-0"
                checked={checked}
                onChange={() => onToggle(option)}
              />
              <span>{option}</span>
            </label>
          );
        })}
      </div>
    </div>
  );
}

function FlowsRouteComponent() {
  const [flowMap, setFlowMap] = useState<Map<string, FlowEntry>>(() => new Map());
  const [, startTransition] = useTransition();
  const flowsList = useMemo(() => {
    return Array.from(flowMap.values()).sort((a, b) => {
      const aTime = new Date(a.updatedAt).getTime();
      const bTime = new Date(b.updatedAt).getTime();
      return bTime - aTime;
    });
  }, [flowMap]);
  const [searchTerm, setSearchTerm] = useState('');
  const [methodFilter, setMethodFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState<number[]>([]);
  const [domainFilter, setDomainFilter] = useState<string[]>([]);
  const [scopeFilter, setScopeFilter] = useState<string[]>([]);
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [pluginTagFilter, setPluginTagFilter] = useState<string[]>([]);
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [editingFlow, setEditingFlow] = useState<FlowEntry | null>(null);
  const [editDraft, setEditDraft] = useState('');
  const [editConfirmed, setEditConfirmed] = useState(false);
  const [showDiff, setShowDiff] = useState(true);
  const [isSubmittingEdit, setIsSubmittingEdit] = useState(false);
  const listRef = useRef<HTMLDivElement | null>(null);
  const eventQueueRef = useRef<FlowEvent[]>([]);
  const flushTimeoutRef = useRef<number | null>(null);

  const applyBatch = useCallback((items: FlowEvent[]) => {
    setFlowMap((previous) => {
      const next = new Map(previous);
      for (const item of items) {
        const flowId = item.id.replace(/:(request|response)$/i, '');
        const existing = next.get(flowId);
        const updated = integrateFlowEvent(existing, item);
        next.set(flowId, updated);
      }
      return next;
    });
  }, []);

  const commitBatch = useCallback(
    (items: FlowEvent[]) => {
      if (items.length === 0) {
        return;
      }
      startTransition(() => {
        applyBatch(items);
      });
    },
    [applyBatch, startTransition]
  );

  const flushPendingEvents = useCallback(() => {
    if (eventQueueRef.current.length === 0) {
      return;
    }
    const batch = eventQueueRef.current.splice(0, eventQueueRef.current.length);
    commitBatch(batch);
  }, [commitBatch]);

  const scheduleFlush = useCallback(() => {
    if (flushTimeoutRef.current !== null) {
      return;
    }
    flushTimeoutRef.current = window.setTimeout(() => {
      flushTimeoutRef.current = null;
      flushPendingEvents();
    }, 16);
  }, [flushPendingEvents]);

  useEffect(() => {
    let cancelled = false;
    setInitialLoading(true);
    listFlows({ limit: 200 })
      .then((page) => {
        if (cancelled) {
          return;
        }
        commitBatch(page.items);
        setCursor(page.nextCursor ?? null);
        setHasMore(Boolean(page.nextCursor));
      })
      .catch((error) => {
        console.error('Failed to load flows', error);
        toast.error('Unable to load captured flows');
      })
      .finally(() => {
        if (!cancelled) {
          setInitialLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [commitBatch]);

  useEffect(() => {
    let cancelled = false;
    let handle: FlowStreamHandle | undefined;

    streamFlowEvents(
      STREAM_ID,
      (event) => {
        if (!cancelled) {
          eventQueueRef.current.push(event);
          if (eventQueueRef.current.length >= 250) {
            flushPendingEvents();
          } else {
            scheduleFlush();
          }
        }
      }
    )
      .then((value) => {
        if (cancelled) {
          void value.close();
          return;
        }
        handle = value;
      })
      .catch((error) => {
        console.error('Failed to stream flow events', error);
        toast.error('Unable to subscribe to live flow updates');
      });

    return () => {
      cancelled = true;
      if (handle) {
        handle
          .close()
          .catch((error) => console.warn('Failed to close flow stream', error));
      }
      if (flushTimeoutRef.current !== null) {
        window.clearTimeout(flushTimeoutRef.current);
        flushTimeoutRef.current = null;
      }
      eventQueueRef.current = [];
    };
  }, [flushPendingEvents, scheduleFlush]);

  const methodOptions = useMemo(() => {
    return Array.from(
      new Set(
        flowsList
          .map((flow) => flow.method)
          .filter((value): value is string => Boolean(value))
      )
    ).sort();
  }, [flowsList]);

  const statusOptions = useMemo(() => {
    return Array.from(
      new Set(
        flowsList
          .map((flow) => flow.statusCode)
          .filter((value): value is number => typeof value === 'number')
      )
    ).sort((a, b) => a - b);
  }, [flowsList]);

  const domainOptions = useMemo(() => {
    return Array.from(
      new Set(
        flowsList
          .map((flow) => flow.domain ?? flow.host)
          .filter((value): value is string => Boolean(value))
      )
    ).sort();
  }, [flowsList]);

  const scopeOptions = useMemo(() => {
    return Array.from(new Set(flowsList.map((flow) => flow.scope))).sort();
  }, [flowsList]);

  const tagOptions = useMemo(() => {
    const all = new Set<string>();
    for (const flow of flowsList) {
      for (const tag of flow.tags) {
        all.add(tag);
      }
    }
    return Array.from(all).sort();
  }, [flowsList]);

  const pluginTagOptions = useMemo(() => {
    const all = new Set<string>();
    for (const flow of flowsList) {
      for (const tag of flow.pluginTags) {
        all.add(tag);
      }
    }
    return Array.from(all).sort();
  }, [flowsList]);

  const filteredFlows = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    return flowsList.filter((flow) => {
      if (term && !flow.searchText.includes(term)) {
        return false;
      }
      if (methodFilter.length > 0) {
        if (!flow.method || !methodFilter.includes(flow.method)) {
          return false;
        }
      }
      if (statusFilter.length > 0) {
        if (!flow.statusCode || !statusFilter.includes(flow.statusCode)) {
          return false;
        }
      }
      if (domainFilter.length > 0) {
        const domain = flow.domain ?? flow.host ?? '';
        if (!domain || !domainFilter.includes(domain)) {
          return false;
        }
      }
      if (scopeFilter.length > 0 && !scopeFilter.includes(flow.scope)) {
        return false;
      }
      if (tagFilter.length > 0) {
        if (!flow.tags.some((tag) => tagFilter.includes(tag))) {
          return false;
        }
      }
      if (pluginTagFilter.length > 0) {
        if (!flow.pluginTags.some((tag) => pluginTagFilter.includes(tag))) {
          return false;
        }
      }
      return true;
    });
  }, [
    flowsList,
    searchTerm,
    methodFilter,
    statusFilter,
    domainFilter,
    scopeFilter,
    tagFilter,
    pluginTagFilter
  ]);

  useEffect(() => {
    if (filteredFlows.length === 0) {
      return;
    }
    if (!selectedFlowId || !filteredFlows.some((flow) => flow.id === selectedFlowId)) {
      setSelectedFlowId(filteredFlows[0].id);
    }
  }, [filteredFlows, selectedFlowId]);

  const selectedFlow = useMemo(() => {
    if (!selectedFlowId) {
      return null;
    }
    return flowsList.find((flow) => flow.id === selectedFlowId) ?? null;
  }, [flowsList, selectedFlowId]);

  const timelineVirtualizer = useVirtualizer({
    count: filteredFlows.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => ITEM_HEIGHT,
    overscan: 12
  });
  const virtualFlows = timelineVirtualizer.getVirtualItems();

  const diffChunks = useMemo(() => {
    if (!editingFlow) {
      return [] as DiffChunk[];
    }
    return computeDiff(editingFlow.request?.raw ?? '', editDraft);
  }, [editingFlow, editDraft]);

  const clearFilters = () => {
    setMethodFilter([]);
    setStatusFilter([]);
    setDomainFilter([]);
    setScopeFilter([]);
    setTagFilter([]);
    setPluginTagFilter([]);
    setSearchTerm('');
  };

  const loadMore = async () => {
    if (!cursor) {
      return;
    }
    try {
      setIsLoadingMore(true);
      const page = await listFlows({ cursor, limit: 200 });
      commitBatch(page.items);
      setCursor(page.nextCursor ?? null);
      setHasMore(Boolean(page.nextCursor));
    } catch (error) {
      console.error('Failed to load additional flows', error);
      toast.error('Unable to load additional flows');
    } finally {
      setIsLoadingMore(false);
    }
  };

  const beginEdit = (flow: FlowEntry) => {
    if (!flow.request) {
      toast.error('Original request payload unavailable for editing');
      return;
    }
    setEditingFlow(flow);
    setEditDraft(flow.request.raw);
    setEditConfirmed(false);
    setShowDiff(true);
  };

  const submitEdit = async () => {
    if (!editingFlow) {
      return;
    }
    if (!editConfirmed) {
      return;
    }
    try {
      setIsSubmittingEdit(true);
      await resendFlow(editingFlow.id, editDraft);
      toast.success('Modified request dispatched');
      setEditingFlow(null);
      setEditDraft('');
      setEditConfirmed(false);
    } catch (error) {
      console.error('Failed to resend flow', error);
      toast.error('Unable to resend modified request');
    } finally {
      setIsSubmittingEdit(false);
    }
  };

  return (
    <div className="flex h-full min-h-0">
      <aside className="w-72 border-r border-border bg-card px-4 py-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase text-muted-foreground">Filters</h2>
          <Button variant="ghost" size="sm" onClick={clearFilters} className="h-auto px-2 py-1 text-xs">
            Clear
          </Button>
        </div>
        <div className="mt-4 space-y-4">
          <div>
            <label className="text-xs font-semibold uppercase text-muted-foreground" htmlFor="flow-search">
              Search
            </label>
            <div className="relative mt-2">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                id="flow-search"
                type="search"
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                placeholder="Method, URL, body…"
                className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              />
            </div>
          </div>
          <FilterGroup
            title="Methods"
            options={methodOptions}
            selected={methodFilter}
            onToggle={(value) =>
              setMethodFilter((prev) =>
                prev.includes(value) ? prev.filter((item) => item !== value) : [...prev, value]
              )
            }
          />
          <NumberFilterGroup
            title="Status"
            options={statusOptions}
            selected={statusFilter}
            onToggle={(value) =>
              setStatusFilter((prev) =>
                prev.includes(value) ? prev.filter((item) => item !== value) : [...prev, value]
              )
            }
          />
          <FilterGroup
            title="Domains"
            options={domainOptions}
            selected={domainFilter}
            onToggle={(value) =>
              setDomainFilter((prev) =>
                prev.includes(value) ? prev.filter((item) => item !== value) : [...prev, value]
              )
            }
            emptyLabel="Unknown domain"
          />
          <FilterGroup
            title="Scope"
            options={scopeOptions}
            selected={scopeFilter}
            onToggle={(value) =>
              setScopeFilter((prev) =>
                prev.includes(value) ? prev.filter((item) => item !== value) : [...prev, value]
              )
            }
          />
          <FilterGroup
            title="Tags"
            options={tagOptions}
            selected={tagFilter}
            onToggle={(value) =>
              setTagFilter((prev) =>
                prev.includes(value) ? prev.filter((item) => item !== value) : [...prev, value]
              )
            }
          />
          <FilterGroup
            title="Plugin tags"
            options={pluginTagOptions}
            selected={pluginTagFilter}
            onToggle={(value) =>
              setPluginTagFilter((prev) =>
                prev.includes(value) ? prev.filter((item) => item !== value) : [...prev, value]
              )
            }
          />
        </div>
      </aside>
      <section className="flex min-h-0 flex-1">
        <div className="flex w-[420px] min-w-[320px] flex-col border-r border-border">
          <div className="border-b border-border px-4 py-3">
            <h1 className="text-lg font-semibold text-foreground">Flow timeline</h1>
            <p className="text-sm text-muted-foreground">
              Real-time intercepted requests and responses with live updates.
            </p>
          </div>
          <div ref={listRef} className="flex-1 overflow-y-auto px-3 py-2">
            {initialLoading && filteredFlows.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> Loading flows…
              </div>
            ) : filteredFlows.length === 0 ? (
              <div className="flex h-full items-center justify-center px-4 text-center text-sm text-muted-foreground">
                No flows match the current filters.
              </div>
            ) : (
              <div
                style={{ height: `${timelineVirtualizer.getTotalSize()}px`, position: 'relative' }}
              >
                {virtualFlows.map((virtualFlow) => {
                  const flow = filteredFlows[virtualFlow.index];
                  if (!flow) {
                    return null;
                  }
                  return (
                    <div
                      key={virtualFlow.key}
                      data-index={virtualFlow.index}
                      ref={timelineVirtualizer.measureElement}
                      className="pb-2"
                      style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        right: 0,
                        transform: `translateY(${virtualFlow.start}px)`
                      }}
                    >
                      <FlowListItem
                        flow={flow}
                        selected={flow.id === selectedFlowId}
                        onSelect={() => setSelectedFlowId(flow.id)}
                      />
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          {hasMore && (
            <div className="border-t border-border p-3">
              <Button
                variant="outline"
                className="w-full"
                onClick={loadMore}
                disabled={isLoadingMore || !cursor}
              >
                <RefreshCw className={cn('mr-2 h-4 w-4', isLoadingMore && 'animate-spin')} />
                {isLoadingMore ? 'Loading…' : 'Load more'}
              </Button>
            </div>
          )}
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          {selectedFlow ? (
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="border-b border-border px-6 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-3">
                      <span
                        className={cn(
                          'rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wide',
                          getMethodTone(selectedFlow.method)
                        )}
                      >
                        {selectedFlow.method ?? '—'}
                      </span>
                      <h2 className="truncate text-xl font-semibold text-foreground">
                        {selectedFlow.path ?? selectedFlow.url ?? selectedFlow.id}
                      </h2>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
                      <span>{selectedFlow.host ?? 'Unknown host'}</span>
                      <span className={cn(
                        'rounded-full px-2 py-0.5 text-xs font-semibold uppercase',
                        getStatusTone(selectedFlow.statusCode)
                      )}>
                        {selectedFlow.statusCode
                          ? `${selectedFlow.statusCode}${
                              selectedFlow.statusText ? ` ${selectedFlow.statusText}` : ''
                            }`
                          : 'Awaiting response'}
                      </span>
                      <span className={cn(
                        'rounded-full px-2 py-0.5 text-xs font-semibold uppercase',
                        selectedFlow.scope === 'out-of-scope'
                          ? 'bg-amber-500/10 text-amber-500'
                          : 'bg-emerald-500/10 text-emerald-500'
                      )}>
                        {selectedFlow.scope.replace('-', ' ')}
                      </span>
                      <span className="flex items-center gap-1">
                        <Timer className="h-4 w-4" /> {formatDuration(selectedFlow.durationMs)}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                      {selectedFlow.tags.map((tag) => (
                        <span key={tag} className="rounded-full bg-muted px-2 py-0.5">
                          #{tag}
                        </span>
                      ))}
                      {selectedFlow.pluginTags.map((tag) => (
                        <span key={`plugin-${tag}`} className="rounded-full bg-muted/60 px-2 py-0.5">
                          Plugin:{' '}
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-3">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={isLoadingMore}
                      onClick={() => {
                        setInitialLoading(true);
                        listFlows({ limit: 200 })
                          .then((page) => {
                            setFlowMap(() => {
                              const map = new Map<string, FlowEntry>();
                              for (const item of page.items) {
                                const flowId = item.id.replace(/:(request|response)$/i, '');
                                const existing = map.get(flowId);
                                const updated = integrateFlowEvent(existing, item);
                                map.set(flowId, updated);
                              }
                              return map;
                            });
                            setCursor(page.nextCursor ?? null);
                            setHasMore(Boolean(page.nextCursor));
                          })
                          .catch((error) => {
                            console.error('Failed to refresh flows', error);
                            toast.error('Unable to refresh flows');
                          })
                          .finally(() => setInitialLoading(false));
                      }}
                    >
                      <RefreshCw className="mr-2 h-4 w-4" /> Refresh
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => beginEdit(selectedFlow)}
                      disabled={!selectedFlow.request}
                    >
                      <Send className="mr-2 h-4 w-4" /> Edit & resend
                    </Button>
                  </div>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto px-6 py-6">
                <section>
                  <header className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold uppercase text-muted-foreground">Request</h3>
                      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                        <span>Size {formatBytes(selectedFlow.requestSize)}</span>
                        {selectedFlow.requestSize && selectedFlow.requestSize > LARGE_BODY_THRESHOLD && (
                          <span className="flex items-center gap-1 text-orange-500">
                            <Filter className="h-3 w-3" /> Large payload
                          </span>
                        )}
                        {selectedFlow.requestTruncated && (
                          <span className="flex items-center gap-1 text-amber-500">
                            <AlertTriangle className="h-3 w-3" /> Truncated
                          </span>
                        )}
                        {selectedFlow.requestRedacted && (
                          <span className="flex items-center gap-1 text-sky-500">
                            <Shield className="h-3 w-3" /> Sanitized
                          </span>
                        )}
                        {selectedFlow.requestBinary && (
                          <span className="flex items-center gap-1 text-purple-500">
                            Binary
                          </span>
                        )}
                      </div>
                    </div>
                  </header>
                  <HttpMessageViewer message={selectedFlow.request} />
                </section>
                <section className="mt-8">
                  <header className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold uppercase text-muted-foreground">Response</h3>
                      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                        <span>Size {formatBytes(selectedFlow.responseSize)}</span>
                        {selectedFlow.responseSize &&
                          selectedFlow.responseSize > LARGE_BODY_THRESHOLD && (
                            <span className="flex items-center gap-1 text-orange-500">
                              <Filter className="h-3 w-3" /> Large payload
                            </span>
                          )}
                        {selectedFlow.responseTruncated && (
                          <span className="flex items-center gap-1 text-amber-500">
                            <AlertTriangle className="h-3 w-3" /> Truncated
                          </span>
                        )}
                        {selectedFlow.responseRedacted && (
                          <span className="flex items-center gap-1 text-sky-500">
                            <Shield className="h-3 w-3" /> Sanitized
                          </span>
                        )}
                        {selectedFlow.responseBinary && (
                          <span className="flex items-center gap-1 text-purple-500">
                            Binary
                          </span>
                        )}
                      </div>
                    </div>
                  </header>
                  <HttpMessageViewer message={selectedFlow.response} />
                </section>
              </div>
            </div>
          ) : (
            <div className="flex flex-1 items-center justify-center p-6 text-sm text-muted-foreground">
              Select a flow from the timeline to inspect the intercepted request and response.
            </div>
          )}
        </div>
      </section>
      {editingFlow && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="w-full max-w-3xl rounded-lg border border-border bg-background shadow-xl">
            <div className="flex items-start justify-between border-b border-border px-6 py-4">
              <div>
                <h2 className="text-lg font-semibold text-foreground">Modify request &amp; resend</h2>
                <p className="text-sm text-muted-foreground">
                  Editing sanitized requests can expose sensitive data. Review changes carefully before dispatching.
                </p>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setEditingFlow(null)}>
                Close
              </Button>
            </div>
            <div className="space-y-4 px-6 py-6">
              <div>
                <label className="text-xs font-semibold uppercase text-muted-foreground" htmlFor="edit-draft">
                  Request payload
                </label>
                <textarea
                  id="edit-draft"
                  value={editDraft}
                  onChange={(event) => setEditDraft(event.target.value)}
                  className="mt-2 h-64 w-full rounded-md border border-border bg-card p-3 font-mono text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-destructive"
                />
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    id="confirm-send"
                    type="checkbox"
                    className="h-3 w-3 rounded border-border text-destructive focus-visible:outline-none focus-visible:ring-0"
                    checked={editConfirmed}
                    onChange={(event) => setEditConfirmed(event.target.checked)}
                  />
                  <label htmlFor="confirm-send" className="cursor-pointer">
                    I understand this will send a modified request to the upstream service.
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="ghost" onClick={() => setShowDiff((value) => !value)} size="sm">
                    {showDiff ? 'Hide diff' : 'Show diff'}
                  </Button>
                </div>
              </div>
              {showDiff && (
                <div className="max-h-72 overflow-auto rounded-md border border-border bg-card">
                  <pre className="whitespace-pre-wrap break-words p-4 text-xs font-mono leading-relaxed">
                    {diffChunks.length === 0
                      ? 'No changes detected.'
                      : diffChunks.map((chunk, index) => {
                          const prefix = chunk.type === 'add' ? '+' : chunk.type === 'remove' ? '-' : ' ';
                          return (
                            <div
                              key={`${chunk.type}-${index}`}
                              className={cn(
                                'whitespace-pre-wrap break-words',
                                chunk.type === 'add' && 'bg-emerald-500/10 text-emerald-500',
                                chunk.type === 'remove' && 'bg-destructive/10 text-destructive line-through'
                              )}
                            >
                              {`${prefix} ${chunk.value || ' '}`}
                            </div>
                          );
                        })}
                  </pre>
                </div>
              )}
              <div className="flex items-center justify-end gap-3">
                <Button variant="ghost" onClick={() => setEditingFlow(null)}>
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  onClick={submitEdit}
                  disabled={
                    !editConfirmed ||
                    isSubmittingEdit ||
                    !editingFlow.request ||
                    editDraft.trim().length === 0
                  }
                >
                  {isSubmittingEdit ? 'Sending…' : 'Resend modified request'}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export const Route = createFileRoute('/flows')({
  component: FlowsRouteComponent
});

export default FlowsRouteComponent;
