import { Link } from "react-router-dom";
import { useMemo, useState } from "react";
import { useQueries } from "@tanstack/react-query";
import { Filter, Search, ShieldAlert } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { useScansList } from "@/api/queries";
import { api } from "@/api/client";
import type { ScanRecord, VulnSummary } from "@/types/api";
import { normalizeSeverity, timeAgo } from "@/lib/utils";

interface FlatFinding extends VulnSummary {
  scan_id: string;
  scan_target: string;
  scan_started_at: string;
}

export default function FindingsPage() {
  const { data: scans } = useScansList();
  const ids = useMemo(() => (scans ?? []).slice(0, 30).map((s) => s.id), [scans]);

  const scanQueries = useQueries({
    queries: ids.map((id) => ({
      queryKey: ["scan", id],
      queryFn: () => api.getScan(id),
      staleTime: 30_000,
    })),
  });

  const isLoading = scanQueries.some((q) => q.isLoading);

  const findings = useMemo<FlatFinding[]>(() => {
    const out: FlatFinding[] = [];
    scanQueries.forEach((q) => {
      const rec = q.data as ScanRecord | undefined;
      if (!rec?.vulns) return;
      rec.vulns.forEach((v) =>
        out.push({
          ...v,
          scan_id: rec.id,
          scan_target: rec.target,
          scan_started_at: rec.started_at,
        }),
      );
    });
    out.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    return out;
  }, [scanQueries]);

  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<string>("all");

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severity !== "all" && normalizeSeverity(f.severity) !== severity) return false;
      if (!query) return true;
      const q = query.toLowerCase();
      return (
        (f.title || "").toLowerCase().includes(q) ||
        (f.endpoint || "").toLowerCase().includes(q) ||
        (f.scan_target || "").toLowerCase().includes(q) ||
        (f.cve || "").toLowerCase().includes(q)
      );
    });
  }, [findings, query, severity]);

  const counts = useMemo(() => {
    const out: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    findings.forEach((f) => {
      const sev = normalizeSeverity(f.severity);
      if (out[sev] !== undefined) out[sev] += 1;
    });
    return out;
  }, [findings]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Vulnerabilities across the latest {ids.length} scans, ranked by
            severity.
          </p>
        </div>
        <div className="grid grid-cols-5 gap-1.5 sm:flex sm:gap-2">
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
            const dot =
              s === "critical"
                ? "bg-red-500"
                : s === "high"
                  ? "bg-orange-500"
                  : s === "medium"
                    ? "bg-amber-400"
                    : s === "low"
                      ? "bg-blue-400"
                      : "bg-neutral-500"
            return (
              <div
                key={s}
                className="rounded-md border border-border bg-card px-3 py-2 text-center min-w-[64px]"
              >
                <p className="mono text-lg font-semibold leading-none tabular-nums">
                  {counts[s] ?? 0}
                </p>
                <p className="mt-1 flex items-center justify-center gap-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                  <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
                  {s}
                </p>
              </div>
            )
          })}
        </div>
      </div>

      <Card>
        <CardContent className="flex flex-col gap-3 p-3 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by title, endpoint, host, or CVE…"
              className="pl-8"
            />
          </div>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger className="w-full sm:w-44">
              <Filter className="h-3.5 w-3.5" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="info">Info</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      <Card className="overflow-hidden">
        {isLoading && findings.length === 0 ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="h-6 w-6" />}
            title="No matching findings"
            description="Try widening your filters or run a new scan."
          />
        ) : (
          <ul className="divide-y divide-border">
            {filtered.map((f) => (
              <li key={`${f.scan_id}:${f.id}`} className="px-4 py-3 text-sm hover:bg-muted/30">
                <Link to={`/scans/${f.scan_id}`} className="block">
                  <div className="flex flex-wrap items-start gap-2">
                    <SeverityBadge severity={f.severity} />
                    <p className="flex-1 font-medium text-foreground truncate">
                      {f.title}
                    </p>
                    <span className="mono text-[11px] text-muted-foreground">
                      {timeAgo(f.scan_started_at)}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                    <span className="mono truncate max-w-[36ch]">{f.endpoint || f.scan_target}</span>
                    {f.cve && (
                      <Badge variant="outline" className="mono text-[10px]">
                        {f.cve}
                      </Badge>
                    )}
                    {typeof f.cvss === "number" && f.cvss > 0 && (
                      <span className="mono">CVSS {f.cvss.toFixed(1)}</span>
                    )}
                    <span className="ml-auto truncate">→ {f.scan_target}</span>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function severityRank(s: string) {
  switch (normalizeSeverity(s)) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
    default:
      return 0;
  }
}
