import { useNavigate } from "react-router-dom";
import { useMemo, useState, type FormEvent } from "react";
import { ChevronLeft, Loader2, Play } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { PHASES } from "@/components/phase-progress";
import { useStartScan } from "@/api/queries";
import { cn } from "@/lib/utils";

const SCAN_MODES = [
  {
    value: "single",
    label: "Single target",
    hint: "Test exactly what you provided. No subdomain enumeration.",
  },
  {
    value: "wildcard",
    label: "Wildcard / multi",
    hint: "Enumerate subdomains, then scan each one.",
  },
  {
    value: "dast",
    label: "DAST",
    hint: "Authenticated app testing with browser-driven probes.",
  },
];

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

export default function NewScanPage() {
  const nav = useNavigate();
  const startScan = useStartScan();

  const [targetsText, setTargetsText] = useState("");
  const [name, setName] = useState("");
  const [scanMode, setScanMode] = useState("single");
  const [instruction, setInstruction] = useState("");
  const [selectedPhases, setSelectedPhases] = useState<number[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [model, setModel] = useState("");
  const [error, setError] = useState<string | null>(null);

  const targets = useMemo(
    () =>
      targetsText
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean),
    [targetsText],
  );

  function togglePhase(id: number) {
    setSelectedPhases((cur) =>
      cur.includes(id) ? cur.filter((p) => p !== id) : [...cur, id].sort((a, b) => a - b),
    );
  }
  function toggleSeverity(s: string) {
    setSeverityFilter((cur) =>
      cur.includes(s) ? cur.filter((p) => p !== s) : [...cur, s],
    );
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!targets.length) {
      setError("At least one target is required.");
      return;
    }
    try {
      const res = await startScan.mutateAsync({
        targets,
        name: name.trim() || undefined,
        scan_mode: scanMode,
        instruction: instruction.trim() || undefined,
        phases: selectedPhases.length ? selectedPhases : undefined,
        severity_filter: severityFilter.length ? severityFilter : undefined,
        model: model.trim() || undefined,
      });
      const id =
        (res as { id?: string; instance_id?: string })?.instance_id ||
        (res as { id?: string })?.id;
      if (id) nav(`/scans/${id}`);
      else nav("/scans");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => nav(-1)}
          className="text-muted-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" /> Back
        </Button>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-balance">
          Start a new scan
        </h1>
        <p className="mt-1 text-sm text-muted-foreground text-pretty">
          Configure target, scope, and methodology phases. Xalgorix orchestrates
          recon and active probes, then synthesizes findings with the agent.
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Targets</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="targets">Targets *</Label>
              <Textarea
                id="targets"
                required
                placeholder={"example.com\nhttps://app.example.com"}
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
                rows={3}
                className="mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground">
                One per line, or comma-separated. Domains, hosts, or URLs.
              </p>
              {targets.length > 1 && (
                <div className="flex flex-wrap gap-1">
                  {targets.map((t) => (
                    <Badge key={t} variant="outline" className="mono text-[10px]">
                      {t}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="name">Display name (optional)</Label>
              <Input
                id="name"
                placeholder="Auto-generated from target if blank"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Scan mode</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-3">
              {SCAN_MODES.map((m) => (
                <button
                  type="button"
                  key={m.value}
                  onClick={() => setScanMode(m.value)}
                  className={cn(
                    "rounded-md border border-border bg-card p-3 text-left transition-colors",
                    "hover:border-foreground/30",
                    scanMode === m.value &&
                      "border-primary/70 bg-primary/5 ring-1 ring-primary/30",
                  )}
                >
                  <div className="text-sm font-medium">{m.label}</div>
                  <p className="mt-1 text-[11px] text-muted-foreground text-pretty">
                    {m.hint}
                  </p>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Methodology phases
              <span className="ml-2 text-[11px] font-normal text-muted-foreground">
                {selectedPhases.length
                  ? `${selectedPhases.length} selected`
                  : "all phases (default)"}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {PHASES.map((p) => {
                const active = selectedPhases.includes(p.id);
                return (
                  <button
                    type="button"
                    key={p.id}
                    onClick={() => togglePhase(p.id)}
                    className={cn(
                      "flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 text-left text-xs transition-colors",
                      "hover:border-foreground/30",
                      active && "border-primary/70 bg-primary/5 text-foreground",
                      !active && "text-muted-foreground",
                    )}
                  >
                    <span
                      className={cn(
                        "mono inline-flex h-5 w-7 shrink-0 items-center justify-center rounded text-[10px]",
                        active
                          ? "bg-primary/15 text-primary"
                          : "bg-muted text-muted-foreground",
                      )}
                    >
                      {String(p.id).padStart(2, "0")}
                    </span>
                    <span className="truncate">{p.name}</span>
                  </button>
                );
              })}
            </div>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => setSelectedPhases([])}
              >
                All phases
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => setSelectedPhases([1, 22])}
              >
                Recon + report only
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Refinement</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Severity filter</Label>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map((s) => {
                  const active = severityFilter.includes(s);
                  return (
                    <button
                      type="button"
                      key={s}
                      onClick={() => toggleSeverity(s)}
                      className={cn(
                        "rounded-full border px-2.5 py-1 text-[11px] capitalize transition-colors",
                        active
                          ? "border-primary/60 bg-primary/10 text-foreground"
                          : "border-border bg-card text-muted-foreground hover:text-foreground",
                      )}
                    >
                      {s}
                    </button>
                  );
                })}
              </div>
              <p className="text-[11px] text-muted-foreground">
                Report only findings at or above selected severities. Leave blank
                for all.
              </p>
            </div>
            <Separator />
            <div className="space-y-2">
              <Label htmlFor="instr">Custom instruction</Label>
              <Textarea
                id="instr"
                placeholder="e.g. Focus on the payment flow at /checkout and skip /static/."
                value={instruction}
                onChange={(e) => setInstruction(e.target.value)}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label>Model override</Label>
              <Select value={model || "default"} onValueChange={(v) => setModel(v === "default" ? "" : v)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">Server default</SelectItem>
                  <SelectItem value="openai/gpt-5">openai/gpt-5</SelectItem>
                  <SelectItem value="openai/gpt-5-mini">openai/gpt-5-mini</SelectItem>
                  <SelectItem value="anthropic/claude-opus-4.6">anthropic/claude-opus-4.6</SelectItem>
                  <SelectItem value="google/gemini-3-flash">google/gemini-3-flash</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        <div className="sticky bottom-0 flex items-center justify-end gap-2 border-t border-border bg-background/95 py-3 backdrop-blur">
          <Button type="button" variant="outline" onClick={() => nav(-1)}>
            Cancel
          </Button>
          <Button type="submit" disabled={!targets.length || startScan.isPending}>
            {startScan.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            Start scan
          </Button>
        </div>
      </form>
    </div>
  );
}
