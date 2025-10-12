import { useEffect, useMemo, useState } from 'react';
import { save } from '@tauri-apps/api/dialog';
import { AlertTriangle, Download, Eye, EyeOff, Loader2, Shield } from 'lucide-react';
import { toast } from 'sonner';

import { Button } from './ui/button';
import {
  prepareCrashReport,
  saveCrashReport,
  type CrashFilePreview,
  type CrashPreview
} from '../lib/ipc';

function formatFileSize(bytes: number) {
  if (bytes <= 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

type CrashDiagnosticsProps = {
  errorMessage?: string;
};

type LoadState = 'idle' | 'loading' | 'error' | 'ready';

type ExpandedState = Record<string, boolean>;

export function CrashDiagnostics({ errorMessage }: CrashDiagnosticsProps) {
  const [state, setState] = useState<LoadState>('loading');
  const [preview, setPreview] = useState<CrashPreview | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setState('loading');
    prepareCrashReport()
      .then((result) => {
        if (cancelled) {
          return;
        }
        setPreview(result);
        setState('ready');
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setLoadError(error instanceof Error ? error.message : String(error));
        setState('error');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const warnings = useMemo(() => preview?.warnings ?? [], [preview?.warnings]);

  const toggleExpanded = (file: CrashFilePreview) => {
    setExpanded((current) => ({ ...current, [file.name]: !current[file.name] }));
  };

  const handleSave = async () => {
    if (isSaving) {
      return;
    }
    try {
      setIsSaving(true);
      const suggested = `glyph-crash-${Date.now()}.tar.gz`;
      const target = await save({
        defaultPath: suggested,
        filters: [{ name: 'Glyph crash bundle', extensions: ['tar.gz'] }]
      });
      if (!target) {
        return;
      }
      const destination = target.endsWith('.tar.gz') ? target : `${target}.tar.gz`;
      await saveCrashReport(destination);
      toast.success(`Crash bundle saved to ${destination}`);
    } catch (error) {
      console.error('Failed to save crash report bundle', error);
      toast.error('Failed to save crash bundle');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="flex h-full flex-col items-center justify-center bg-background px-6 py-8">
      <div className="w-full max-w-4xl rounded-3xl border border-border bg-card p-8 shadow-2xl">
        <header className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-8 w-8 text-amber-500" aria-hidden />
            <div>
              <h1 className="text-2xl font-semibold text-foreground">Glyph hit an unrecoverable error</h1>
              <p className="text-sm text-muted-foreground">
                We gathered a diagnostic bundle so maintainers can reproduce the crash. Review every file below before sharing.
              </p>
            </div>
          </div>
          {errorMessage ? (
            <p className="rounded-md border border-destructive/50 bg-destructive/10 px-4 py-2 text-sm text-destructive">
              {errorMessage}
            </p>
          ) : null}
        </header>

        <section className="mt-6 space-y-3">
          {state === 'loading' ? (
            <div className="flex items-center gap-2 rounded-lg border border-dashed border-border px-4 py-6 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              Collecting crash diagnostics…
            </div>
          ) : null}
          {state === 'error' ? (
            <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
              Unable to collect diagnostics: {loadError ?? 'Unknown error'}
            </div>
          ) : null}
          {warnings.map((warning) => (
            <div
              key={warning}
              className="flex items-start gap-2 rounded-lg border border-amber-300/60 bg-amber-100/40 px-4 py-3 text-sm text-amber-900 dark:border-amber-500/60 dark:bg-amber-500/10 dark:text-amber-100"
            >
              <Shield className="mt-0.5 h-4 w-4" aria-hidden />
              <span>{warning}</span>
            </div>
          ))}
        </section>

        {state === 'ready' && preview ? (
          <section className="mt-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-foreground">Bundle contents</h2>
                <p className="text-sm text-muted-foreground">
                  Generated at {new Date(preview.generatedAt).toLocaleString()}
                </p>
              </div>
              <Button onClick={handleSave} disabled={isSaving} className="gap-2">
                {isSaving ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Download className="h-4 w-4" aria-hidden />}
                Save crash bundle
              </Button>
            </div>

            <ul className="space-y-4">
              {preview.files.map((file) => {
                const isExpanded = expanded[file.name] ?? false;
                return (
                  <li key={file.name} className="rounded-xl border border-border bg-muted/30 p-4">
                    <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                      <div>
                        <h3 className="text-base font-semibold text-foreground">{file.name}</h3>
                        <p className="text-sm text-muted-foreground">{file.description}</p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {formatFileSize(file.size)} · sha256:{file.sha256}
                        </p>
                        {file.redacted ? (
                          <p className="mt-2 inline-flex items-center gap-2 rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-1 text-xs text-sky-900 dark:text-sky-100">
                            <Shield className="h-3 w-3" aria-hidden />
                            Sensitive values replaced with [REDACTED]
                          </p>
                        ) : null}
                      </div>
                      <Button
                        variant="secondary"
                        onClick={() => toggleExpanded(file)}
                        className="w-full gap-2 md:w-auto"
                      >
                        {isExpanded ? <EyeOff className="h-4 w-4" aria-hidden /> : <Eye className="h-4 w-4" aria-hidden />}
                        {isExpanded ? 'Hide contents' : 'Preview contents'}
                      </Button>
                    </div>
                    {isExpanded ? (
                      <div className="mt-3 max-h-72 overflow-auto rounded-lg border border-border/80 bg-background/80 p-3 text-xs font-mono text-foreground">
                        {file.snippet.trim() ? (
                          <pre className="whitespace-pre-wrap break-words">{file.snippet}</pre>
                        ) : (
                          <p className="text-muted-foreground">File is empty.</p>
                        )}
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </section>
        ) : null}
      </div>
    </div>
  );
}
