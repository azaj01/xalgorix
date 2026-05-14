import { useEffect, useMemo, useState, type ReactNode } from "react"
import { Link, useNavigate, useParams } from "react-router-dom"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Separator } from "@/components/ui/separator"
import { ScanStatusPill } from "@/components/scan-status-pill"
import { SeverityBadge } from "@/components/severity-badge"
import { PhaseProgress, PHASES } from "@/components/phase-progress"
import { CopyButton } from "@/components/copy-button"
import { ErrorState, EmptyState } from "@/components/states"
import { useScan, useStopInstance, useStartSavedInstance, useDeleteScan } from "@/api/queries"
import { api } from "@/api/client"
import {
  filterEventsForInstance,
  mergeFeedEvents,
  toFeedEvent,
  useWSStore,
  type FeedEvent,
} from "@/store/ws"
import { timeAgo, formatTime, formatDuration, severityRank, normalizeSeverity, cn } from "@/lib/utils"
import {
  ChevronLeft,
  Download,
  X,
  Play,
  Trash2,
  ShieldAlert,
  Terminal,
  Sparkles,
  ListChecks,
  ArrowRight,
} from "lucide-react"
import { LiveFeed, type FeedFilter } from "@/components/live-feed"
import type { SubScanSummary, VulnSummary } from "@/types/api"

export default function ScanDetailPage() {
  const navigate = useNavigate()
  const { scanId } = useParams<{ scanId: string }>()
  const id = scanId ?? ""
  const { data: scan, isLoading, isFetching, error, refetch } = useScan(id)
  const stop = useStopInstance()
  const start = useStartSavedInstance()
  const del = useDeleteScan()
  const subscribe = useWSStore((s) => s.subscribe)
  const unsubscribe = useWSStore((s) => s.unsubscribe)
  const liveEvents = useWSStore((s) => s.events)
  const subscriptionId = scan?.instance_id || scan?.id || id

  useEffect(() => {
    if (!subscriptionId) return
    subscribe(subscriptionId)
    return () => unsubscribe()
  }, [subscriptionId, subscribe, unsubscribe])

  if (error)
    return (
      <ErrorState
        title="Could not load scan"
        description={error instanceof Error ? error.message : "Unknown error"}
        action={<Button size="sm" variant="outline" onClick={() => refetch()}>Retry</Button>}
      />
    )
  if (isLoading) return <ScanDetailSkeleton />
  if (!scan)
    return (
      <ErrorState
        title="Scan details are starting"
        description={
          isFetching
            ? "Waiting for the running scan record to become available."
            : "The scan route is open, but the backend has not returned the scan record yet."
        }
        action={<Button size="sm" variant="outline" onClick={() => refetch()}>Retry</Button>}
      />
    )

  const status = (scan.status || "").toLowerCase()
  const canStop = status === "running" || status === "paused"
  const canStart = status === "saved" || status === "stopped" || status === "failed" || status === "finished"

  // Combine persisted events from the scan record with the live websocket
  // feed for this instance, deduped by content.
  const eventInstanceId = scan.instance_id || scan.id || id
  const wsForScan = filterEventsForInstance(liveEvents, eventInstanceId)
  const persistedAsFeed: FeedEvent[] = (scan.events ?? []).map((e, i) =>
    toFeedEvent(e, `scan:${eventInstanceId}`, i),
  )
  const mergedEvents = mergeFeedEvents(persistedAsFeed, wsForScan)

  return (
    <>
      <div>
        <Link to="/scans" className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground">
          <ChevronLeft className="mr-1 h-3 w-3" />
          All scans
        </Link>
      </div>

      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2 min-w-0">
          <div className="flex items-center gap-3 min-w-0">
            <h1 className="font-mono text-2xl font-semibold tracking-tight text-foreground truncate">
              {scan.target}
            </h1>
            <CopyButton value={scan.target} />
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span className="mono">{scan.id}</span>
            <span>·</span>
            <span>Started {timeAgo(scan.started_at)}</span>
            <span>·</span>
            <span>Duration {formatDuration(scan.started_at, scan.finished_at)}</span>
            {scan.scan_mode && (
              <>
                <span>·</span>
                <Badge variant="outline" className="font-normal capitalize">{scan.scan_mode}</Badge>
              </>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <ScanStatusPill status={scan.status} />
          <Button variant="outline" size="sm" asChild>
            <a href={api.reportUrl(scan.id)} target="_blank" rel="noreferrer">
              <Download className="mr-1 h-4 w-4" /> Report
            </a>
          </Button>
          {canStart && (
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                start.mutate(scan.id, {
                  onSuccess: (res) => {
                    if (res.instance_id) {
                      navigate(`/scans/${res.instance_id}`)
                    } else {
                      void refetch()
                    }
                  },
                })
              }
              disabled={start.isPending}
            >
              <Play className="mr-1 h-4 w-4" /> Start
            </Button>
          )}
          {canStop && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => stop.mutate(scan.id)}
              disabled={stop.isPending}
            >
              <X className="mr-1 h-4 w-4" /> Stop
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              if (window.confirm("Permanently delete this scan and all its events?")) {
                del.mutate(scan.id, {
                  onSuccess: () => {
                    navigate("/scans", { replace: true })
                  },
                })
              }
            }}
            disabled={del.isPending}
          >
            <Trash2 className="mr-1 h-4 w-4" /> Delete
          </Button>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm">Phase progress</CardTitle>
            <CardDescription>
              Xalgorix runs a 10-phase autonomous methodology. Currently:{" "}
              <span className="text-foreground">
                {currentPhaseLabel(scan.current_phase)}
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <PhaseProgress
              current={scan.current_phase}
              selected={scan.phases}
              status={scan.status}
            />
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
              {PHASES.map((p) => (
                <div
                  key={p.id}
                  className={cn(
                    "rounded-md border border-border bg-muted/20 px-2 py-1.5 text-[11px]",
                    scan.current_phase === p.id && "border-amber-400/50 text-amber-300",
                  )}
                >
                  <span className="text-muted-foreground mono mr-1.5">{p.id}</span>
                  {p.name}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Risk overview</CardTitle>
            <CardDescription>{(scan.vulns ?? []).length} findings</CardDescription>
          </CardHeader>
          <CardContent>
            <RiskBreakdown vulns={scan.vulns ?? []} />
          </CardContent>
        </Card>

        {!!scan.sub_scan_total && (
          <Card className="lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-sm">Wildcard coverage</CardTitle>
              <CardDescription>
                {scan.sub_scan_completed ?? 0} scanned · {scan.sub_scan_running ?? 0} running ·{" "}
                {scan.sub_scan_remaining ?? 0} remaining
              </CardDescription>
            </CardHeader>
            <CardContent>
              <SubdomainProgress
                completed={scan.sub_scan_completed ?? 0}
                running={scan.sub_scan_running ?? 0}
                remaining={scan.sub_scan_remaining ?? 0}
                total={scan.sub_scan_total ?? 0}
              />
            </CardContent>
          </Card>
        )}
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">
            <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
            Findings
          </TabsTrigger>
          <TabsTrigger value="events">
            <Terminal className="mr-1.5 h-3.5 w-3.5" />
            Events
          </TabsTrigger>
          {!!scan.sub_scan_total && (
            <TabsTrigger value="subdomains">
              <ListChecks className="mr-1.5 h-3.5 w-3.5" />
              Subdomains
            </TabsTrigger>
          )}
          <TabsTrigger value="config">
            <ListChecks className="mr-1.5 h-3.5 w-3.5" />
            Config
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-2">
          <FindingsTab vulns={scan.vulns ?? []} />
        </TabsContent>
        <TabsContent value="events">
          <EventsTab events={mergedEvents} scanId={scan.id} target={scan.target} />
        </TabsContent>
        {!!scan.sub_scan_total && (
          <TabsContent value="subdomains">
            <SubdomainsTab subScans={scan.sub_scans ?? []} />
          </TabsContent>
        )}
        <TabsContent value="config">
          <ConfigTab scan={scan} />
        </TabsContent>
      </Tabs>
    </>
  )
}

function currentPhaseLabel(p?: number): string {
  if (!p) return "—"
  const found = PHASES.find((x) => x.id === p)
  return found ? `${p}. ${found.name}` : `Phase ${p}`
}

function SubdomainProgress({
  completed,
  running,
  remaining,
  total,
}: {
  completed: number
  running: number
  remaining: number
  total: number
}) {
  const denominator = Math.max(total, 1)
  const completedPct = (completed / denominator) * 100
  const runningPct = (running / denominator) * 100
  const remainingPct = Math.max(0, 100 - completedPct - runningPct)
  return (
    <div className="space-y-3">
      <div className="flex h-2 overflow-hidden rounded-sm bg-muted">
        <div className="bg-success" style={{ width: `${completedPct}%` }} />
        <div className="bg-warning" style={{ width: `${runningPct}%` }} />
        <div className="bg-muted-foreground/25" style={{ width: `${remainingPct}%` }} />
      </div>
      <div className="grid gap-2 text-xs sm:grid-cols-4">
        <ProgressStat label="Total" value={total} />
        <ProgressStat label="Scanned" value={completed} />
        <ProgressStat label="Running" value={running} />
        <ProgressStat label="Remaining" value={remaining} />
      </div>
    </div>
  )
}

function ProgressStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mono mt-1 text-lg text-foreground">{value}</div>
    </div>
  )
}

function RiskBreakdown({ vulns }: { vulns: VulnSummary[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const v of vulns) {
      c[normalizeSeverity(v.severity)] += 1
    }
    return c
  }, [vulns])
  const total = vulns.length || 1
  const order: Array<keyof typeof counts> = ["critical", "high", "medium", "low", "info"]
  return (
    <div className="space-y-3">
      <div className="flex items-end gap-1">
        {order.map((sev) => {
          const n = counts[sev as string]
          if (!n) return null
          const pct = Math.max(4, Math.round((n / total) * 100))
          return (
            <div
              key={sev}
              className={cn(
                "h-12 rounded-sm",
                sev === "critical" && "bg-red-500/70",
                sev === "high" && "bg-orange-500/70",
                sev === "medium" && "bg-amber-400/70",
                sev === "low" && "bg-blue-400/70",
                sev === "info" && "bg-neutral-500/60",
              )}
              style={{ width: `${pct}%` }}
              title={`${sev}: ${n}`}
            />
          )
        })}
        {vulns.length === 0 && (
          <div className="h-12 w-full rounded-sm border border-dashed border-border" />
        )}
      </div>
      <div className="grid grid-cols-5 gap-1.5 text-[11px]">
        {order.map((sev) => (
          <div key={sev} className="rounded-md border border-border bg-muted/20 px-2 py-1.5">
            <div className="text-muted-foreground uppercase tracking-wide">{sev}</div>
            <div className="mono text-base text-foreground">{counts[sev as string]}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function SubdomainsTab({ subScans }: { subScans: SubScanSummary[] }) {
  if (subScans.length === 0) {
    return (
      <EmptyState
        title="No subdomains recorded yet"
        description="Discovered subdomains will appear here as the wildcard scan progresses."
      />
    )
  }

  return (
    <Card>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <Th>Subdomain</Th>
                <Th>Status</Th>
                <Th>Findings</Th>
                <Th>Tokens</Th>
                <Th>Started</Th>
              </tr>
            </thead>
            <tbody>
              {subScans.map((sub) => (
                <tr key={sub.id || sub.target} className="border-b border-border/60 last:border-0">
                  <Td>
                    <div className="mono text-sm text-foreground">{sub.target}</div>
                    <div className="mono text-xs text-muted-foreground">{sub.id}</div>
                  </Td>
                  <Td>
                    <ScanStatusPill status={sub.status} />
                  </Td>
                  <Td className="mono text-xs">{sub.vuln_count ?? 0}</Td>
                  <Td className="mono text-xs text-muted-foreground">
                    {sub.total_tokens ? sub.total_tokens.toLocaleString() : "—"}
                  </Td>
                  <Td className="text-muted-foreground">
                    {sub.started_at ? timeAgo(sub.started_at) : "—"}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}

function Th({
  children,
  className = "",
}: {
  children: ReactNode
  className?: string
}) {
  return <th className={cn("px-4 py-3 text-left font-medium", className)}>{children}</th>
}

function Td({
  children,
  className = "",
}: {
  children: ReactNode
  className?: string
}) {
  return <td className={cn("px-4 py-3 align-middle", className)}>{children}</td>
}

function FindingsTab({ vulns }: { vulns: VulnSummary[] }) {
  const [selected, setSelected] = useState<VulnSummary | null>(null)
  const sorted = useMemo(
    () => [...vulns].sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    [vulns],
  )
  if (sorted.length === 0)
    return (
      <EmptyState
        title="No findings yet"
        description="Vulnerabilities will appear here as the engagement progresses."
      />
    )

  return (
    <>
      <div className="space-y-2">
        {sorted.map((f) => (
          <Card key={f.id} id={`finding-${f.id}`} className="overflow-hidden">
            <button
              type="button"
              className="group block w-full text-left transition-colors hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              onClick={() => setSelected(f)}
              aria-label={`Open finding details for ${f.title}`}
            >
              <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0 space-y-1 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <h3 className="font-medium text-foreground">{f.title}</h3>
                    {f.cve && (
                      <Badge variant="outline" className="mono">{f.cve}</Badge>
                    )}
                  </div>
                  {f.description && (
                    <p className="text-sm leading-relaxed text-muted-foreground line-clamp-3">
                      {f.description}
                    </p>
                  )}
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    {f.target && <span className="mono">{f.target}</span>}
                    {f.endpoint && <span className="mono">{f.endpoint}</span>}
                    {f.method && <span className="mono">{f.method}</span>}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  {f.cvss != null && f.cvss > 0 && (
                    <Badge variant="outline" className="mono">CVSS {f.cvss.toFixed(1)}</Badge>
                  )}
                  <span className="inline-flex items-center gap-1 text-xs text-muted-foreground group-hover:text-foreground">
                    Details <ArrowRight className="h-3.5 w-3.5" />
                  </span>
                </div>
              </CardContent>
            </button>
          </Card>
        ))}
      </div>
      <FindingDetailsDialog finding={selected} onOpenChange={(open) => !open && setSelected(null)} />
    </>
  )
}

function FindingDetailsDialog({
  finding,
  onOpenChange,
}: {
  finding: VulnSummary | null
  onOpenChange: (open: boolean) => void
}) {
  return (
    <Dialog open={!!finding} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto">
        {finding && (
          <>
            <DialogHeader>
              <div className="flex flex-wrap items-center gap-2 pr-8">
                <SeverityBadge severity={finding.severity} />
                {finding.cve && <Badge variant="outline" className="mono">{finding.cve}</Badge>}
                {finding.cvss != null && finding.cvss > 0 && (
                  <Badge variant="outline" className="mono">CVSS {finding.cvss.toFixed(1)}</Badge>
                )}
              </div>
              <DialogTitle className="pr-8 text-lg">{finding.title}</DialogTitle>
              <DialogDescription>
                {finding.description || "Detailed vulnerability record from this scan."}
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-3 rounded-md border border-border bg-muted/20 p-3 text-sm sm:grid-cols-2">
              <DetailRow label="Target" value={finding.target} mono />
              <DetailRow label="Endpoint" value={finding.endpoint} mono />
              <DetailRow label="Method" value={finding.method} mono />
              <DetailRow label="CVSS vector" value={finding.cvss_vector} mono />
              <DetailRow label="Finding ID" value={finding.id} mono />
              <DetailRow label="Verification" value={finding.verification_method} />
            </div>

            <Separator />

            <div className="space-y-4">
              <DetailSection title="Impact" value={finding.impact} />
              <DetailSection title="Technical analysis" value={finding.technical_analysis} />
              <DetailSection title="Proof of concept" value={finding.poc_description} />
              {finding.poc_script && (
                <DetailSection title="PoC script" value={finding.poc_script} code />
              )}
              {finding.exploitation_proof && (
                <DetailSection title="Exploitation proof" value={finding.exploitation_proof} code />
              )}
              <DetailSection title="Remediation" value={finding.remediation} />
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string
  value?: string
  mono?: boolean
}) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={cn("mt-1 break-words text-foreground", mono && "mono text-xs")}>
        {value || "—"}
      </div>
    </div>
  )
}

function DetailSection({
  title,
  value,
  code,
}: {
  title: string
  value?: string
  code?: boolean
}) {
  if (!value) return null
  return (
    <section className="space-y-2">
      <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {title}
      </h4>
      {code ? (
        <pre className="max-h-64 overflow-auto rounded-md border border-border bg-black/40 p-3 text-xs leading-relaxed text-foreground">
          <code>{value}</code>
        </pre>
      ) : (
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground/90">
          {value}
        </p>
      )}
    </section>
  )
}

function EventsTab({
  events,
  scanId,
  target,
}: {
  events: FeedEvent[]
  scanId: string
  target: string
}) {
  const [filter, setFilter] = useState<FeedFilter>("all")
  return (
    <LiveFeed
      events={events}
      filter={filter}
      onFilterChange={setFilter}
      exportFilePrefix={`xalgorix-${target || scanId}-events`}
      exportScope={scanId}
      emptyTitle="No events yet"
      emptyDescription="Once the scan starts producing output it will stream here."
    />
  )
}

function ConfigTab({ scan }: { scan: NonNullable<ReturnType<typeof useScan>["data"]> }) {
  const items: Array<{ k: string; v: ReactNode }> = [
    { k: "Scan mode", v: scan.scan_mode || "—" },
    { k: "Severity filter", v: (scan.severity_filter ?? []).join(", ") || "all" },
    { k: "Phases", v: (scan.phases ?? []).join(", ") || "all" },
    { k: "Iterations", v: <span className="mono">{scan.iterations}</span> },
    { k: "Tool calls", v: <span className="mono">{scan.tool_calls}</span> },
    { k: "Tokens", v: <span className="mono">{scan.total_tokens?.toLocaleString() ?? 0}</span> },
    { k: "Stop reason", v: scan.stop_reason || "—" },
    { k: "Started", v: formatTime(scan.started_at) },
    { k: "Finished", v: scan.finished_at ? formatTime(scan.finished_at) : "—" },
    { k: "Discord webhook", v: scan.discord_webhook_configured || scan.discord_webhook ? "configured" : "none" },
  ]
  return (
    <Card>
      <CardContent className="p-0">
        <dl className="divide-y divide-border/60">
          {items.map((it) => (
            <div key={it.k} className="grid grid-cols-3 gap-2 px-4 py-3 text-sm">
              <dt className="text-muted-foreground">{it.k}</dt>
              <dd className="col-span-2 text-foreground">{it.v}</dd>
            </div>
          ))}
          {scan.instruction && (
            <div className="grid grid-cols-3 gap-2 px-4 py-3 text-sm">
              <dt className="text-muted-foreground flex items-center gap-1">
                <Sparkles className="h-3 w-3" /> Instruction
              </dt>
              <dd className="col-span-2 whitespace-pre-wrap text-foreground/90">
                {scan.instruction}
              </dd>
            </div>
          )}
        </dl>
      </CardContent>
    </Card>
  )
}

function ScanDetailSkeleton() {
  return (
    <>
      <Skeleton className="h-4 w-24" />
      <Skeleton className="h-10 w-2/3" />
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-40 lg:col-span-2" />
        <Skeleton className="h-40" />
      </div>
      <Skeleton className="h-10 w-72" />
      <Skeleton className="h-96 w-full" />
    </>
  )
}
