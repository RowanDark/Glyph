import { createFileRoute } from '@tanstack/react-router';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowUpRight,
  CheckCircle2,
  ClipboardCopy,
  Download,
  FileCode,
  Filter,
  StickyNote,
  ThumbsDown,
  ThumbsUp
} from 'lucide-react';
import mermaid from 'mermaid';
import { z } from 'zod';

import { Button } from '../components/ui/button';
import { CASES, type CaseSeverity } from '../lib/cases';
import { cn } from '../lib/utils';
import { toast } from 'sonner';

const severityOrder: Record<CaseSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4
};

const severityCopy: Record<CaseSeverity, { label: string; tone: string }> = {
  critical: { label: 'Critical', tone: 'bg-red-500/10 text-red-500 border-red-500/30' },
  high: { label: 'High', tone: 'bg-amber-500/10 text-amber-500 border-amber-500/30' },
  medium: { label: 'Medium', tone: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30' },
  low: { label: 'Low', tone: 'bg-sky-500/10 text-sky-500 border-sky-500/30' },
  informational: { label: 'Informational', tone: 'bg-muted text-muted-foreground border-border' }
};

const sarifSchema = z.object({
  version: z.literal('2.1.0'),
  $schema: z.string(),
  runs: z.array(
    z.object({
      tool: z.object({
        driver: z.object({
          name: z.string(),
          informationUri: z.string().optional()
        })
      }),
      artifacts: z
        .array(
          z.object({
            location: z.object({
              uri: z.string()
            }),
            description: z.object({ text: z.string() }).optional()
          })
        )
        .optional(),
      results: z.array(
        z.object({
          ruleId: z.string(),
          level: z.enum(['error', 'warning', 'note']),
          message: z.object({ text: z.string() }),
          locations: z.array(
            z.object({
              physicalLocation: z.object({
                artifactLocation: z.object({ uri: z.string() }),
                region: z.object({ startLine: z.number().int().min(1) }).optional()
              })
            })
          )
        })
      )
    })
  )
});

const jsonlSchema = z.object({
  id: z.string(),
  severity: z.string(),
  asset: z.string(),
  confidence: z.number(),
  summary: z.string()
});

const tabOptions = ['summary', 'evidence', 'repro', 'graph'] as const;
type TabKey = (typeof tabOptions)[number];

function formatConfidence(confidence: number) {
  return `${confidence.toFixed(0)}%`;
}

function severityToSarifLevel(severity: CaseSeverity) {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

function useMermaid(graphDefinition: string) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!ref.current) {
      return;
    }

    let isCancelled = false;

    const renderGraph = async () => {
      try {
        mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' });
        const { svg } = await mermaid.render(`graph-${Math.random().toString(16).slice(2)}`, graphDefinition);
        if (!isCancelled && ref.current) {
          ref.current.innerHTML = svg;
        }
      } catch (error) {
        console.error('Failed to render mermaid graph', error);
        if (!isCancelled && ref.current) {
          ref.current.innerHTML = '<pre class="text-destructive">Unable to render graph</pre>';
        }
      }
    };

    void renderGraph();

    return () => {
      isCancelled = true;
    };
  }, [graphDefinition]);

  return ref;
}

function CaseExplorer() {
  const [severityFilter, setSeverityFilter] = useState<CaseSeverity[]>([]);
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [activeCaseId, setActiveCaseId] = useState(CASES[0]?.id ?? '');
  const [activeTab, setActiveTab] = useState<TabKey>('summary');
  const [notes, setNotes] = useState<Record<string, string[]>>({});
  const [noteDraft, setNoteDraft] = useState('');
  const [disposition, setDisposition] = useState<Record<string, 'tp' | 'fp' | undefined>>({});
  const caseListRef = useRef<HTMLDivElement | null>(null);

  const allTags = useMemo(() => Array.from(new Set(CASES.flatMap((item) => item.tags))).sort(), []);

  const filteredCases = useMemo(() => {
    return CASES.filter((item) => {
      const severityMatch = severityFilter.length === 0 || severityFilter.includes(item.severity);
      const tagMatch = tagFilter.length === 0 || item.tags.some((tag) => tagFilter.includes(tag));
      return severityMatch && tagMatch;
    }).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  }, [severityFilter, tagFilter]);

  useEffect(() => {
    if (!filteredCases.find((item) => item.id === activeCaseId)) {
      setActiveCaseId(filteredCases[0]?.id ?? '');
    }
  }, [filteredCases, activeCaseId]);

  const activeCase = useMemo(
    () => filteredCases.find((item) => item.id === activeCaseId) ?? filteredCases[0],
    [filteredCases, activeCaseId]
  );

  const caseVirtualizer = useVirtualizer({
    count: filteredCases.length,
    getScrollElement: () => caseListRef.current,
    estimateSize: () => 220,
    overscan: 8
  });
  const virtualCaseItems = caseVirtualizer.getVirtualItems();

  const mermaidRef = useMermaid(activeCase?.graph ?? '');

  const escapeHtml = (value: string) =>
    String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  const handleExport = async (format: 'sarif' | 'jsonl' | 'html') => {
    if (!activeCase) {
      return;
    }

    try {
      let data = '';
      let mime = 'application/json';
      let filename = `${activeCase.id.toLowerCase()}`;

      if (format === 'sarif') {
        const sarif = {
          version: '2.1.0',
          $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
          runs: [
            {
              tool: {
                driver: {
                  name: 'Glyph AI Investigator',
                  informationUri: 'https://glyph.sh'
                }
              },
              artifacts: activeCase.evidence.map((item) => ({
                location: { uri: item.link ?? item.title.replace(/\s+/g, '-').toLowerCase() },
                description: { text: item.description }
              })),
              results: [
                {
                  ruleId: activeCase.id,
                  level: severityToSarifLevel(activeCase.severity),
                  message: { text: activeCase.summary },
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: activeCase.asset },
                        region: { startLine: 1 }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        } as const;

        sarifSchema.parse(sarif);
        data = JSON.stringify(sarif, null, 2);
        filename += '.sarif';
      } else if (format === 'jsonl') {
        const jsonl = {
          id: activeCase.id,
          severity: activeCase.severity,
          asset: activeCase.asset,
          confidence: activeCase.confidence,
          summary: activeCase.summary
        };
        jsonlSchema.parse(jsonl);
        data = `${JSON.stringify(jsonl)}\n`;
        filename += '.jsonl';
      } else {
        const html = `<!doctype html><html lang="en"><head><meta charset="utf-8" />\n<title>${escapeHtml(
          activeCase.title
        )}</title></head><body>\n<h1>${escapeHtml(activeCase.title)}</h1>\n<p><strong>Severity:</strong> ${escapeHtml(
          severityCopy[activeCase.severity].label
        )}</p>\n<p><strong>Asset:</strong> ${escapeHtml(activeCase.asset)}</p>\n<p>${escapeHtml(activeCase.summary)}</p>\n<h2>Deduped findings</h2><ul>${activeCase.dedupedFindings
          .map((finding) => `<li>${escapeHtml(finding)}</li>`)
          .join('')}</ul>\n</body></html>`;
        data = html;
        mime = 'text/html';
        filename += '.html';
      }

      const blob = new Blob([data], { type: mime });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      anchor.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported ${activeCase.id} as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Failed to export case', error);
      toast.error('Export failed – please try again.');
    }
  };

  const handleCopyPoc = async () => {
    if (!activeCase) {
      return;
    }

    try {
      await navigator.clipboard.writeText(activeCase.poc);
      toast.success('Proof of concept copied to clipboard');
    } catch (error) {
      console.error('Clipboard copy failed', error);
      toast.error('Unable to copy to clipboard');
    }
  };

  const handleAddNote = () => {
    if (!activeCase || noteDraft.trim().length === 0) {
      return;
    }

    setNotes((prev) => {
      const existing = prev[activeCase.id] ?? [];
      return {
        ...prev,
        [activeCase.id]: [...existing, noteDraft.trim()]
      };
    });
    setNoteDraft('');
    toast.success('Note added to case');
  };

  if (!activeCase) {
    return (
      <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-center gap-3 p-6 text-center text-muted-foreground">
        <FileCode className="h-10 w-10" />
        <p>No cases match the current filters.</p>
      </div>
    );
  }

  return (
    <div className="mx-auto flex w-full max-w-6xl gap-6 p-6">
      <aside className="w-80 shrink-0 space-y-6">
        <section className="rounded-lg border border-border bg-card p-4">
          <header className="mb-4 flex items-center gap-2 text-sm font-semibold text-muted-foreground">
            <Filter className="h-4 w-4" />
            <span>Filters</span>
          </header>
          <div className="space-y-4">
            <div>
              <p className="mb-2 text-xs font-semibold uppercase text-muted-foreground">Severity</p>
              <div className="flex flex-wrap gap-2">
                {(Object.keys(severityCopy) as CaseSeverity[]).map((level) => {
                  const isSelected = severityFilter.includes(level);
                  return (
                    <button
                      key={level}
                      type="button"
                      onClick={() => {
                        setSeverityFilter((prev) =>
                          prev.includes(level) ? prev.filter((item) => item !== level) : [...prev, level]
                        );
                      }}
                      className={cn(
                        'rounded-full border px-3 py-1 text-xs font-medium transition',
                        severityCopy[level].tone,
                        isSelected ? 'ring-2 ring-offset-2 ring-offset-background ring-primary' : 'opacity-80 hover:opacity-100'
                      )}
                    >
                      {severityCopy[level].label}
                    </button>
                  );
                })}
              </div>
            </div>
            <div>
              <p className="mb-2 text-xs font-semibold uppercase text-muted-foreground">Tags</p>
              <div className="flex flex-wrap gap-2">
                {allTags.map((tag) => {
                  const isSelected = tagFilter.includes(tag);
                  return (
                    <button
                      key={tag}
                      type="button"
                      onClick={() => {
                        setTagFilter((prev) =>
                          prev.includes(tag) ? prev.filter((item) => item !== tag) : [...prev, tag]
                        );
                      }}
                      className={cn(
                        'rounded-full border border-border bg-background px-3 py-1 text-xs font-medium text-muted-foreground transition hover:text-foreground',
                        isSelected && 'border-primary/40 text-foreground'
                      )}
                    >
                      #{tag}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </section>
        <section className="rounded-lg border border-border bg-card">
          <header className="border-b border-border px-4 py-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Cases ({filteredCases.length})
          </header>
          <div ref={caseListRef} className="max-h-[calc(100vh-240px)] overflow-y-auto p-3">
            {filteredCases.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                No cases match the selected filters.
              </div>
            ) : (
              <div
                style={{ height: `${caseVirtualizer.getTotalSize()}px`, position: 'relative' }}
              >
                {virtualCaseItems.map((virtualItem) => {
                  const item = filteredCases[virtualItem.index];
                  if (!item) {
                    return null;
                  }
                  const isActive = activeCase?.id === item.id;
                  return (
                    <div
                      key={virtualItem.key}
                      data-index={virtualItem.index}
                      ref={caseVirtualizer.measureElement}
                      className="pb-2"
                      style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        right: 0,
                        transform: `translateY(${virtualItem.start}px)`
                      }}
                    >
                      <button
                        type="button"
                        onClick={() => {
                          setActiveCaseId(item.id);
                          setActiveTab('summary');
                        }}
                        className={cn(
                          'w-full rounded-lg border px-3 py-3 text-left transition',
                          isActive
                            ? 'border-primary/40 bg-primary/10 text-foreground'
                            : 'border-transparent bg-background text-muted-foreground hover:border-border hover:text-foreground'
                        )}
                      >
                        <div className="flex items-center justify-between text-xs uppercase">
                          <span className="font-semibold">{item.id}</span>
                          <span
                            className={cn(
                              'rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide',
                              severityCopy[item.severity].tone
                            )}
                          >
                            {severityCopy[item.severity].label}
                          </span>
                        </div>
                        <p className="mt-2 text-sm font-medium text-foreground">{item.title}</p>
                        <p className="mt-1 text-xs text-muted-foreground">{item.asset}</p>
                        <div className="mt-3 flex items-center justify-between text-xs">
                          <span className="text-muted-foreground">Confidence</span>
                          <span className="font-semibold text-foreground">
                            {formatConfidence(item.confidence)}
                          </span>
                        </div>
                        <div className="mt-1 h-1.5 rounded-full bg-muted">
                          <div
                            className="h-full rounded-full bg-primary"
                            style={{ width: `${Math.min(100, Math.max(0, item.confidence))}%` }}
                          />
                        </div>
                        <div className="mt-3 flex flex-wrap gap-1">
                          {item.tags.map((tag) => (
                            <span
                              key={tag}
                              className="rounded-full bg-muted px-2 py-0.5 text-[10px] uppercase tracking-wide"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </section>
      </aside>
      <section className="flex flex-1 flex-col gap-6">
        {activeCase ? (
          <>
            <header className="rounded-lg border border-border bg-card p-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-3">
                    <span className="rounded-full border px-3 py-1 text-xs font-semibold uppercase text-muted-foreground">
                      {severityCopy[activeCase.severity].label}
                    </span>
                    <span className="rounded-full bg-secondary px-3 py-1 text-xs font-semibold uppercase text-secondary-foreground">
                      {activeCase.asset}
                    </span>
                  </div>
                  <h1 className="mt-4 text-3xl font-semibold text-foreground">{activeCase.title}</h1>
                  <p className="mt-2 max-w-3xl text-sm text-muted-foreground">{activeCase.summary}</p>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                    {activeCase.tags.map((tag) => (
                      <span key={tag} className="rounded-full border border-border px-2 py-1">#{tag}</span>
                    ))}
                  </div>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-2 text-sm text-muted-foreground">
                  <span className="text-xs uppercase">Confidence</span>
                  <span className="text-2xl font-semibold text-foreground">{formatConfidence(activeCase.confidence)}</span>
                  <div className="h-2 w-32 rounded-full bg-muted">
                    <div
                      className="h-full rounded-full bg-primary"
                      style={{ width: `${Math.min(100, Math.max(0, activeCase.confidence))}%` }}
                    />
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <Button
                      size="sm"
                      variant={disposition[activeCase.id] === 'tp' ? 'default' : 'outline'}
                      className="gap-2"
                      onClick={() => {
                        setDisposition((prev) => ({ ...prev, [activeCase.id]: prev[activeCase.id] === 'tp' ? undefined : 'tp' }));
                        toast.success('Marked as true positive');
                      }}
                    >
                      <ThumbsUp className="h-4 w-4" />
                      TP
                    </Button>
                    <Button
                      size="sm"
                      variant={disposition[activeCase.id] === 'fp' ? 'destructive' : 'outline'}
                      className="gap-2"
                      onClick={() => {
                        setDisposition((prev) => ({ ...prev, [activeCase.id]: prev[activeCase.id] === 'fp' ? undefined : 'fp' }));
                        toast.success('Marked as false positive');
                      }}
                    >
                      <ThumbsDown className="h-4 w-4" />
                      FP
                    </Button>
                  </div>
                </div>
              </div>
              <div className="mt-6 flex flex-wrap gap-2">
                <Button size="sm" variant="secondary" className="gap-2" onClick={() => handleExport('sarif')}>
                  <Download className="h-4 w-4" />
                  Export SARIF
                </Button>
                <Button size="sm" variant="secondary" className="gap-2" onClick={() => handleExport('jsonl')}>
                  <Download className="h-4 w-4" />
                  Export JSONL
                </Button>
                <Button size="sm" variant="secondary" className="gap-2" onClick={() => handleExport('html')}>
                  <Download className="h-4 w-4" />
                  Export HTML
                </Button>
                <Button size="sm" variant="outline" className="gap-2" onClick={handleCopyPoc}>
                  <ClipboardCopy className="h-4 w-4" />
                  Copy POC
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="gap-2"
                  onClick={() => {
                    const notesForCase = notes[activeCase.id] ?? [];
                    toast.info(
                      notesForCase.length > 0
                        ? `Notes (${notesForCase.length}) already captured.`
                        : 'No analyst notes yet.'
                    );
                  }}
                >
                  <StickyNote className="h-4 w-4" />
                  Notes ({(notes[activeCase.id] ?? []).length})
                </Button>
              </div>
            </header>

            <nav className="flex gap-2">
              {tabOptions.map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setActiveTab(tab)}
                  className={cn(
                    'rounded-md border px-4 py-2 text-sm font-medium capitalize transition',
                    activeTab === tab
                      ? 'border-primary/50 bg-primary/10 text-foreground'
                      : 'border-border bg-card text-muted-foreground hover:text-foreground'
                  )}
                >
                  {tab === 'graph' ? 'Chain Graph' : tab}
                </button>
              ))}
            </nav>

            <article className="flex-1 rounded-lg border border-border bg-card p-6">
              {activeTab === 'summary' && (
                <div className="space-y-6">
                  <section>
                    <h2 className="text-lg font-semibold">Deduped findings</h2>
                    <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-muted-foreground">
                      {activeCase.dedupedFindings.map((finding) => (
                        <li key={finding}>{finding}</li>
                      ))}
                    </ul>
                  </section>
                  <section>
                    <h2 className="text-lg font-semibold">Recommended actions</h2>
                    <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-muted-foreground">
                      {activeCase.recommendedActions.map((action) => (
                        <li key={action}>{action}</li>
                      ))}
                    </ul>
                  </section>
                  <section>
                    <h2 className="text-lg font-semibold">Analyst notes</h2>
                    <div className="mt-3 space-y-3">
                      {(notes[activeCase.id] ?? []).length === 0 ? (
                        <p className="text-sm text-muted-foreground">
                          No notes yet. Capture your investigation decisions below.
                        </p>
                      ) : (
                        <ul className="space-y-2 text-sm text-muted-foreground">
                          {(notes[activeCase.id] ?? []).map((note, index) => (
                            <li
                              key={`${note}-${index}`}
                              className="flex items-start gap-2 rounded-md border border-border bg-background p-3"
                            >
                              <CheckCircle2 className="mt-0.5 h-4 w-4 text-primary" />
                              <span>{note}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                      <div className="rounded-md border border-border bg-background p-4">
                        <label className="block text-xs font-semibold uppercase text-muted-foreground" htmlFor="note">
                          Add note
                        </label>
                        <textarea
                          id="note"
                          value={noteDraft}
                          onChange={(event) => setNoteDraft(event.target.value)}
                          rows={3}
                          className="mt-2 w-full rounded-md border border-border bg-card p-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
                          placeholder="Document why this case is important, escalated, or closed."
                        />
                        <div className="mt-2 flex justify-end">
                          <Button size="sm" className="gap-2" onClick={handleAddNote}>
                            <StickyNote className="h-4 w-4" />
                            Save note
                          </Button>
                        </div>
                      </div>
                    </div>
                  </section>
                </div>
              )}

              {activeTab === 'evidence' && (
                <div className="space-y-4">
                  {activeCase.evidence.map((item) => (
                    <div key={item.id} className="rounded-lg border border-border bg-background p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-semibold text-foreground">{item.title}</p>
                          <p className="text-xs uppercase text-muted-foreground">{item.type}</p>
                        </div>
                        {item.link && (
                          <a
                            href={item.link}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"
                          >
                            View artifact
                            <ArrowUpRight className="h-3.5 w-3.5" />
                          </a>
                        )}
                      </div>
                      <p className="mt-2 text-sm text-muted-foreground">{item.description}</p>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'repro' && (
                <div className="space-y-6">
                  <section>
                    <h2 className="text-lg font-semibold">Reproduction steps</h2>
                    <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
                      {activeCase.reproSteps.map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ol>
                  </section>
                  <section>
                    <h2 className="text-lg font-semibold">Proof of concept</h2>
                    <pre className="mt-3 overflow-x-auto rounded-md border border-border bg-background p-4 text-xs text-muted-foreground">
                      {activeCase.poc}
                    </pre>
                  </section>
                </div>
              )}

              {activeTab === 'graph' && (
                <div className="space-y-4">
                  <h2 className="text-lg font-semibold">Exploit chain</h2>
                  <div className="rounded-lg border border-border bg-background p-4">
                    <div ref={mermaidRef} className="mermaid" aria-label="Exploit chain graph" />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Diagram rendered with Mermaid describing the attacker flow from entry point to impact.
                  </p>
                </div>
              )}
            </article>
          </>
        ) : (
          <div className="flex flex-1 items-center justify-center rounded-lg border border-border bg-card p-6 text-sm text-muted-foreground">
            Adjust the filters to display at least one case for detailed analysis.
          </div>
        )}
      </section>
    </div>
  );
}

export const Route = createFileRoute('/cases')({
  component: CaseExplorer
});

export default CaseExplorer;
