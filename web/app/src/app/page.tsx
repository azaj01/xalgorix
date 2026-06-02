import { Button } from "@xalgorix/ui";

export default function DashboardHome() {
  return (
    <main className="container py-16">
      <h1 className="text-3xl font-semibold tracking-tight">Dashboard</h1>
      <p className="mt-2 text-muted-foreground">
        Live scan telemetry, findings, and reports will land here.
      </p>
      <div className="mt-6">
        <Button>Start a scan</Button>
      </div>
    </main>
  );
}
