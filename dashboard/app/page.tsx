export default function DashboardPage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-8">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-sentinel-500 mb-4">
          Sentinel WAF
        </h1>
        <p className="text-gray-400 text-lg mb-8">
          Dashboard initializing — connect the control-plane API to proceed.
        </p>
        <div className="grid grid-cols-3 gap-4 text-sm">
          {[
            { label: "Requests/s", value: "—" },
            { label: "Blocked", value: "—" },
            { label: "Latency p99", value: "—" },
          ].map(({ label, value }) => (
            <div
              key={label}
              className="bg-gray-900 border border-gray-800 rounded-lg p-4"
            >
              <div className="text-gray-500">{label}</div>
              <div className="text-2xl font-mono mt-1">{value}</div>
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}
