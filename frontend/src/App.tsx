import { useEffect, useMemo, useRef, useState } from 'react'
import { Toaster, toast } from 'sonner'

import { Badge } from './components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card'
import { ScrollArea } from './components/ui/scroll-area'

type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

type Alert = {
  module: string
  severity: Severity
  message: string
}

type PacketData = {
  timestamp: string
  src_ip: string | null
  dst_ip: string | null
  src_port: number | null
  dst_port: number | null
  protocol: string
  payload_size: number
  alert?: Alert | null
}

type WsEvent =
  | { type: 'packet'; data: PacketData }
  | { type: 'alert'; data: Alert }

const MAX_PACKETS = 200
const MAX_ALERTS = 50

function App() {
  const [packets, setPackets] = useState<PacketData[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [activeDetections, setActiveDetections] = useState<Record<string, number>>({})
  const [connected, setConnected] = useState(false)
  const notifiedAlertsRef = useRef<Set<string>>(new Set())

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${protocol}://${window.location.hostname}:3000/ws`)

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setConnected(false)

    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data) as WsEvent

        if (parsed.type === 'packet') {
          setPackets((current) => [parsed.data, ...current].slice(0, MAX_PACKETS))

          const packetAlert = parsed.data.alert
          if (packetAlert) {
            setActiveDetections((current) => ({
              ...current,
              [packetAlert.module]: (current[packetAlert.module] ?? 0) + 1,
            }))
          }
        }

        if (parsed.type === 'alert') {
          setAlerts((current) => [parsed.data, ...current].slice(0, MAX_ALERTS))

          setActiveDetections((current) => ({
            ...current,
            [parsed.data.module]: (current[parsed.data.module] ?? 0) + 1,
          }))

          const dedupeKey = `${parsed.data.module}-${parsed.data.message}`
          if (
            parsed.data.module === 'PortScanDetector' &&
            !notifiedAlertsRef.current.has(dedupeKey)
          ) {
            notifiedAlertsRef.current.add(dedupeKey)
            toast.error('Port scan detected', {
              description: parsed.data.message,
              duration: 5000,
            })
          }
        }
      } catch {
        // ignore malformed events
      }
    }

    return () => ws.close()
  }, [])

  const detectionCount = useMemo(
    () => Object.keys(activeDetections).length,
    [activeDetections],
  )

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      <Toaster richColors theme="dark" position="top-right" />

      <header className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold">NetLogAnalyzer Dashboard</h1>
        <Badge variant={connected ? 'default' : 'destructive'}>
          {connected ? 'WebSocket Connected' : 'WebSocket Disconnected'}
        </Badge>
      </header>

      <section className="grid gap-4 md:grid-cols-2 mb-6">
        <Card>
          <CardHeader>
            <CardTitle>Total Packets (session)</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold">{packets.length}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active Detections</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold">{detectionCount}</p>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <Card className="min-h-[500px]">
          <CardHeader>
            <CardTitle>Live Packet Stream</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[420px] rounded-md border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-900">
                  <tr className="border-b border-slate-800 text-slate-300">
                    <th className="p-2">Time</th>
                    <th className="p-2">Source</th>
                    <th className="p-2">Destination</th>
                    <th className="p-2">Protocol</th>
                    <th className="p-2">Bytes</th>
                    <th className="p-2">Alert</th>
                  </tr>
                </thead>
                <tbody>
                  {packets.map((packet, idx) => (
                    <tr key={`${packet.timestamp}-${idx}`} className="border-b border-slate-800/70">
                      <td className="p-2">{new Date(packet.timestamp).toLocaleTimeString()}</td>
                      <td className="p-2">{packet.src_ip ?? '-' }:{packet.src_port ?? '-'}</td>
                      <td className="p-2">{packet.dst_ip ?? '-'}:{packet.dst_port ?? '-'}</td>
                      <td className="p-2">{packet.protocol}</td>
                      <td className="p-2">{packet.payload_size}</td>
                      <td className="p-2">
                        {packet.alert ? (
                          <Badge variant={packet.alert.severity === 'HIGH' || packet.alert.severity === 'CRITICAL' ? 'destructive' : 'secondary'}>
                            {packet.alert.severity}
                          </Badge>
                        ) : (
                          '-'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card className="min-h-[500px]">
          <CardHeader>
            <CardTitle>High Severity Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[420px] space-y-2">
              {alerts
                .filter((alert) => alert.severity === 'HIGH' || alert.severity === 'CRITICAL')
                .map((alert, idx) => (
                  <div key={`${alert.module}-${idx}`} className="mb-2 rounded-md border border-red-800 bg-red-950/30 p-3">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="text-sm font-medium">{alert.module}</span>
                      <Badge variant="destructive">{alert.severity}</Badge>
                    </div>
                    <p className="text-xs text-slate-200">{alert.message}</p>
                  </div>
                ))}
            </ScrollArea>
          </CardContent>
        </Card>
      </section>
    </div>
  )
}

export default App
