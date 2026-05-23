import type { ReactNode } from "react"
import { Link } from "react-router-dom"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { EmptyState, ErrorState } from "@/components/states"
import {
  useInstances,
  useStopInstance,
  useStartSavedInstance,
  useRestartInstance,
} from "@/api/queries"
import { ScanStatusPill } from "@/components/scan-status-pill"
import { PhaseProgress } from "@/components/phase-progress"
import { timeAgo, formatDuration, shortId } from "@/lib/utils"
import type { ScanInstance } from "@/types/api"
import {
  Cpu,
  MemoryStick,
  HardDrive,
  Play,
  Square,
  RotateCw,
  Layers,
  Coins,
  ShieldAlert,
  ExternalLink,
} from "lucide-react"

export default function InstancesPage() {
  const { data, isLoading, error, refetch } = useInstances()

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-1">
        <h1 className="font-sans text-2xl font-semibold tracking-tight">Instances</h1>
        <p className="text-sm text-muted-foreground">
          Active scan instances and global host pressure. Completed scans are historical records.
        </p>
      </header>

      {error ? (
        <ErrorState
          title="Could not load instances"
          description={error instanceof Error ? error.message : "Unknown error"}
          action={<Button size="sm" variant="outline" onClick={() => refetch()}>Retry</Button>}
        />
      ) : isLoading ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-48" />
          ))}
        </div>
      ) : (
        <>
          {data?.resources && <ResourcesBar resources={data.resources} />}
          {!data || !data.instances || data.instances.length === 0 ? (
            <EmptyState
              title="No instances"
              description="Start a scan to see it appear here as a running instance."
            />
          ) : (
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {data.instances.map((inst) => (
                <InstanceCard key={inst.id} instance={inst} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function ResourcesBar({ resources }: { resources: NonNullable<ReturnType<typeof useInstances>["data"]>["resources"] }) {
  const cpu = Math.min(100, Math.round((resources.cpu_load_1m / Math.max(1, resources.cpu_cores)) * 100))
  const ramTotal = resources.ram_total_mb || 1
  const ramUsed = ramTotal - resources.ram_available_mb
  const ramPct = Math.min(100, Math.max(0, Math.round((ramUsed / ramTotal) * 100)))
  const diskFreeGb = (resources.disk_free_mb / 1024).toFixed(1)
  const heavyActive = resources.active_heavy_tool_leases ?? 0
  const heavySlots = resources.heavy_tool_slots ?? 0
  const toolMem = resources.tool_mem_limit_mb ?? 0
  const scanMem = resources.scan_memory_budget_mb ?? 0
  const rss = resources.process_rss_mb ?? 0
  const heap = resources.go_heap_alloc_mb ?? 0
  const level = (resources.level || "").toLowerCase()
  const levelColor =
    level === "critical"
      ? "bg-red-500/10 border-red-500/30 text-red-300"
      : level === "caution" || level === "warning" || level === "warn"
        ? "bg-amber-500/10 border-amber-500/30 text-amber-300"
        : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"

  return (
    <Card>
      <CardContent className="grid gap-3 p-4 md:grid-cols-4">
        <ResourceStat
          icon={<Cpu className="h-3 w-3" />}
          label="HOST CPU LOAD"
          value={`${cpu}%`}
          sub={`${resources.cpu_load_1m.toFixed(2)} / ${resources.cpu_cores} cores · heavy ${heavyActive}/${heavySlots}`}
        />
        <ResourceStat
          icon={<MemoryStick className="h-3 w-3" />}
          label="HOST MEMORY"
          value={`${ramPct}%`}
          sub={rss > 0 ? `${Math.round(ramUsed)}MB used · xalgorix ${rss}MB RSS` : `${Math.round(ramUsed)}MB used`}
        />
        <ResourceStat
          icon={<HardDrive className="h-3 w-3" />}
          label="DISK FREE"
          value={`${diskFreeGb}GB`}
          sub={scanMem > 0 ? `Max ${resources.effective_max_instances} · scan ${scanMem}MB · tool ${toolMem}MB` : `Max ${resources.effective_max_instances} instances`}
        />
        <div className={`rounded-md border px-3 py-2 text-xs ${levelColor}`}>
          <div className="uppercase tracking-wide opacity-70">Host resource level</div>
          <div className="mt-0.5 font-medium capitalize">{resources.level || "ok"}</div>
          {shouldShowResourceReason(resources) && (
            <div className="mt-0.5 opacity-70 line-clamp-2">{heap > 0 ? `Go heap ${heap}MB. ` : ""}{resources.reason}</div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

function shouldShowResourceReason(resources?: { level?: string; reason?: string }): boolean {
  const reason = resources?.reason?.trim()
  if (!reason) return false
  const level = (resources?.level || "").trim().toLowerCase()
  return level !== "ok" && !reason.toLowerCase().startsWith("ok")
}

function ResourceStat({
  icon,
  label,
  value,
  sub,
}: {
  icon: ReactNode
  label: string
  value: string
  sub?: string
}) {
  return (
    <div className="rounded-md border border-border bg-muted/30 px-3 py-2">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="mono mt-0.5 text-xl text-foreground">{value}</div>
      {sub && <div className="text-[11px] text-muted-foreground mono">{sub}</div>}
    </div>
  )
}

function InstanceCard({ instance }: { instance: ScanInstance }) {
  const stop = useStopInstance()
  const start = useStartSavedInstance()
  const restart = useRestartInstance()
  const status = (instance.status || "").toLowerCase()
  const canStop = status === "running" || status === "paused"
  const canStart = status === "saved" || status === "stopped" || status === "failed" || status === "finished"

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3 overflow-hidden">
          <div className="min-w-0 flex-1">
            <CardTitle className="truncate mono text-sm">
              {instance.name || instance.targets || shortId(instance.id)}
            </CardTitle>
            <CardDescription className="mono text-xs truncate">
              {shortId(instance.id, 12)}
              {instance.scan_mode && <> · {instance.scan_mode}</>}
            </CardDescription>
          </div>
          <ScanStatusPill status={instance.status} className="shrink-0" />
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-3 gap-2">
          <Stat
            icon={<ShieldAlert className="h-3 w-3" />}
            label="VULNS"
            value={String(instance.vuln_count ?? 0)}
          />
          <Stat
            icon={<Layers className="h-3 w-3" />}
            label="ITERS"
            value={String(instance.iterations ?? 0)}
          />
          <Stat
            icon={<Coins className="h-3 w-3" />}
            label="TOKENS"
            value={
              instance.total_tokens
                ? compactNumber(instance.total_tokens)
                : "0"
            }
          />
        </div>
        <PhaseProgress
          current={instance.current_phase}
          selected={instance.phases}
          status={instance.status}
        />
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2 text-xs text-muted-foreground">
          <div>
            <div>Started {timeAgo(instance.started_at)}</div>
            <div className="mono">
              {formatDuration(instance.started_at, instance.finished_at)}
            </div>
          </div>
          <Button asChild size="sm" variant="ghost" className="h-7">
            <Link to={`/scans/${instance.id}`}>
              Open <ExternalLink className="ml-1 h-3 w-3" />
            </Link>
          </Button>
        </div>
        <div className="flex flex-wrap gap-2 pt-1">
          {canStart && (
            <Button
              size="sm"
              variant="outline"
              disabled={start.isPending}
              onClick={() => start.mutate(instance.id)}
            >
              <Play className="mr-1 h-3.5 w-3.5" /> Start
            </Button>
          )}
          {canStop && (
            <Button
              size="sm"
              variant="outline"
              disabled={stop.isPending}
              onClick={() => stop.mutate(instance.id)}
            >
              <Square className="mr-1 h-3.5 w-3.5" /> Stop
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            disabled={restart.isPending}
            onClick={() => restart.mutate(instance.id)}
          >
            <RotateCw className="mr-1 h-3.5 w-3.5" /> Restart
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function Stat({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/30 p-2">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="mono text-base text-foreground">{value}</div>
    </div>
  )
}

function compactNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return String(n)
}
