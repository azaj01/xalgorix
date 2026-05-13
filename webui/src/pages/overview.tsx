import { useMemo, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { VulnSummary } from "@/types/api";
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  Cpu,
  HardDrive,
  Layers,
  Plus,
  Radio,
  ShieldAlert,
  Target,
} from "lucide-react";
import { MetricCard } from "@/components/metric-card";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { EmptyState, ErrorState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { LiveFeed } from "@/components/live-feed";
import { useWSStore } from "@/store/ws";
import {
  useInstances,
  useQueueStatus,
  useScansList,
  useStatus,
} from "@/api/queries";
import {
  normalizeSeverity,
  severityRank,
  shortId,
  timeAgo,
} from "@/lib/utils";

export default function OverviewPage() {
  const { data: status } = useStatus();
  const { data: instances, isLoading: instancesLoading, error: instancesError } =
    useInstances();
  const { data: scanList } = useScansList();
  const { data: queue } = useQueueStatus();
  const events = useWSStore((s) => s.events);

  const allInstances = instances?.instances ?? [];
  const runningInstances = allInstances.filter((i) => i.status === "running");
  const activeInstance = runningInstances[0];

  const aggregateVulns = useMemo(() => {
    const map = new Map<string, { vuln: VulnSummary; instanceId: string }>();
    for (const inst of allInstances) {
      for (const v of inst.vulns || []) {
        if (!map.has(v.id)) map.set(v.id, { vuln: v, instanceId: inst.id });
      }
    }
    return Array.from(map.values());
  }, [allInstances]);

  const totalFindings = aggregateVulns.length;
  const criticalHigh = aggregateVulns.filter((v) => {
    const s = normalizeSeverity(v.vuln.severity);
    return s === "critical" || s === "high";
  }).length;

  // ScanInstance.targets is a comma-separated string; trim each entry so we
  // collapse "a.com, b.com" and "a.com,b.com" to the same logical target.
  const targetsScanned = new Set(
    allInstances.flatMap((i) =>
      i.targets
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    ),
  ).size;

  const recentScans = allInstances.slice(0, 6);

  const recentCritical = useMemo(() => {
    return [...aggregateVulns]
      .sort((a, b) => severityRank(b.vuln.severity) - severityRank(a.vuln.severity))
      .filter((v) => {
        const s = normalizeSeverity(v.vuln.severity);
        return s === "critical" || s === "high";
      })
      .slice(0, 5);
  }, [aggregateVulns]);

  const resources = instances?.resources;
  const queueCount = queue?.available ? queue.remaining || 0 : 0;

  if (instancesError) {
    return (
      <ErrorState
        title="Failed to load dashboard"
        description={(instancesError as Error).message}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Overview</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Command center for scans, findings, and live activity.
          </p>
        </div>
        <Button asChild>
          <Link to="/scans/new">
            <Plus className="h-3.5 w-3.5" /> New Scan
          </Link>
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <MetricCard
          label="Active"
          value={runningInstances.length}
          hint={
            activeInstance
              ? `${activeInstance.name || activeInstance.targets.split(",")[0]}`
              : "No active scans"
          }
          to={activeInstance ? `/scans/${activeInstance.id}` : "/scans"}
          icon={<Activity className="h-3.5 w-3.5" />}
          accent={runningInstances.length > 0 ? "success" : "default"}
        />
        <MetricCard
          label="Findings"
          value={totalFindings}
          hint={`${scanList?.length || 0} scans on disk`}
          to="/findings"
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
        />
        <MetricCard
          label="Crit / High"
          value={criticalHigh}
          hint={criticalHigh > 0 ? "Needs review" : "All clear"}
          to="/findings"
          icon={<AlertOctagon className="h-3.5 w-3.5" />}
          accent={criticalHigh > 0 ? "critical" : "default"}
        />
        <MetricCard
          label="Targets"
          value={targetsScanned}
          hint={targetsScanned === 1 ? "1 host" : `${targetsScanned} hosts`}
          to="/scans"
          icon={<Target className="h-3.5 w-3.5" />}
        />
        <MetricCard
          label="Phase"
          value={status?.current_phase ?? "—"}
          hint={
            status?.current_phase
              ? `Methodology phase ${status.current_phase}`
              : "Idle"
          }
          icon={<Layers className="h-3.5 w-3.5" />}
        />
        <MetricCard
          label="Queue"
          value={queueCount}
          hint={
            queue?.available
              ? `${queue.targets?.length || 0} total · resumable`
              : "Empty"
          }
          to={queue?.available ? "/scans" : undefined}
          icon={<Radio className="h-3.5 w-3.5" />}
          accent={queueCount > 0 ? "warning" : "default"}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between py-4">
            <CardTitle>Recent Scans</CardTitle>
            <Button asChild size="sm" variant="ghost">
              <Link to="/scans">
                View all <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            {instancesLoading ? (
              <div className="space-y-2 p-4">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-10" />
                ))}
              </div>
            ) : recentScans.length === 0 ? (
              <EmptyState
                title="No scans yet"
                description="Launch your first scan to start collecting findings."
                action={
                  <Button asChild size="sm">
                    <Link to="/scans/new">
                      <Plus className="h-3.5 w-3.5" /> New Scan
                    </Link>
                  </Button>
                }
                className="m-4"
              />
            ) : (
              <div className="divide-y divide-border">
                {recentScans.map((s) => (
                  <Link
                    key={s.id}
                    to={`/scans/${s.id}`}
                    className="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-accent/40"
                  >
                    <ScanStatusPill status={s.status} />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium truncate">
                        {s.name || s.targets.split(",")[0] || "Untitled scan"}
                      </p>
                      <p className="text-xs text-muted-foreground mono truncate">
                        {s.targets}
                      </p>
                    </div>
                    <div className="hidden md:block text-right text-xs text-muted-foreground mono">
                      <div>{s.vuln_count} findings</div>
                      <div>{timeAgo(s.started_at)}</div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between py-4">
            <CardTitle>System Health</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <Row
              icon={<Cpu className="h-3.5 w-3.5" />}
              label="CPU load (1m)"
              value={
                resources
                  ? `${resources.cpu_load_1m?.toFixed(2)} · ${resources.cpu_cores} cores`
                  : "—"
              }
            />
            <Row
              icon={<HardDrive className="h-3.5 w-3.5" />}
              label="RAM available"
              value={
                resources
                  ? `${(resources.ram_available_mb / 1024).toFixed(1)} GB / ${(resources.ram_total_mb / 1024).toFixed(1)} GB`
                  : "—"
              }
            />
            <Row
              icon={<HardDrive className="h-3.5 w-3.5" />}
              label="Disk free"
              value={
                resources
                  ? `${(resources.disk_free_mb / 1024).toFixed(1)} GB`
                  : "—"
              }
            />
            <Row
              icon={<Layers className="h-3.5 w-3.5" />}
              label="Resource level"
              value={
                resources ? (
                  <span className="capitalize">
                    {resources.level} · max {resources.effective_max_instances}
                  </span>
                ) : (
                  "—"
                )
              }
            />
            {resources?.reason && resources.reason !== "" && (
              <p className="rounded border border-border bg-muted/40 px-2 py-1 text-[11px] text-muted-foreground mono">
                {resources.reason}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between py-4">
            <CardTitle>Critical Findings</CardTitle>
            <Button asChild size="sm" variant="ghost">
              <Link to="/findings">
                All findings <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            {recentCritical.length === 0 ? (
              <EmptyState
                title="No critical findings"
                description="Critical and high severity findings appear here as they are discovered."
                className="m-4"
              />
            ) : (
              <ul className="divide-y divide-border">
                {recentCritical.map(({ vuln, instanceId }) => (
                  <li key={`${instanceId}-${vuln.id}`}>
                    {/* Findings deep-link route doesn't exist; route to the
                        owning scan, where the Findings tab renders this vuln. */}
                    <Link
                      to={`/scans/${instanceId}`}
                      className="block px-5 py-3 transition-colors hover:bg-accent/40"
                    >
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={vuln.severity} />
                        <span className="text-sm font-medium truncate">
                          {vuln.title}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground mono truncate">
                        {vuln.endpoint || vuln.target || shortId(instanceId)}
                      </p>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between py-4">
            <CardTitle>Live Activity</CardTitle>
            <Button asChild size="sm" variant="ghost">
              <Link to="/live">
                Open feed <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <LiveFeed
              events={events.slice(-50)}
              filter="all"
              onFilterChange={() => {}}
              showControls={false}
              className="border-0"
              emptyTitle="Waiting for events"
              emptyDescription="When a scan is running, its live events appear here."
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Row({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-2 text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <div className="text-foreground text-right mono">{value}</div>
    </div>
  );
}
