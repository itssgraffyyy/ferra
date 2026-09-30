/**
 * Protocol analysis: exactly what the capture carried.
 *
 * No protocol fact is inferred here. Fields the analyser did not populate
 * render as "not reported", and PFS renders as NOT VERIFIABLE when the capture
 * could not establish it.
 */
import { useAnalysis } from '../App'
import { NOT_VERIFIABLE, hasPayload, payload, show } from '../api/format'
import { Card, Field, Fields, NotVerifiableNote, Table, UnavailableNote } from '../components/ui'
import { NoAnalysis } from '../components/NoAnalysis'

interface EspFlow {
  spi?: string
  packets?: number
  bytes_total?: number
  src?: string
  dst?: string
  first_frame?: number
  last_frame?: number
}

export default function ProtocolView() {
  const { bundle } = useAnalysis()
  if (!bundle) return <NoAnalysis />
  if (!hasPayload(bundle, 'protocol')) {
    return (
      <div className="view">
        <h2>Protocol analysis</h2>
        <UnavailableNote bundle={bundle} stage="protocol" />
      </div>
    )
  }

  const protocol = payload(bundle, 'protocol')
  const details = (protocol.details as Record<string, unknown> | undefined) ?? {}
  const scan = (details.scan as Record<string, unknown> | undefined) ?? {}
  const pfs = (protocol.pfs as Record<string, unknown> | undefined) ?? (details.pfs as Record<string, unknown> | undefined) ?? {}
  const flows = (protocol.esp_flows as EspFlow[] | undefined) ?? []
  const exchanges = (protocol.ike_exchanges as Record<string, unknown>[] | undefined) ?? []

  return (
    <div className="view">
      <h2>Protocol analysis</h2>

      <div className="grid grid-2">
        <Card title="Detection" subtitle="What the analyser saw in the capture">
          <Fields>
            <Field label="Analysis method" value={protocol.method} />
            <Field label="IPsec detected" value={protocol.ipsec_detected} />
            <Field label="IKE version" value={protocol.ike_version} />
            <Field label="Packets" value={protocol.packets ?? scan.packets} />
            <Field label="IKE packets" value={protocol.ike_packets ?? scan.ike_packets} />
            <Field label="ESP packets" value={protocol.esp_packets ?? scan.esp_packets} />
            <Field label="AH packets" value={scan.ah_packets ?? 0} fallback="none seen" />
          </Fields>
        </Card>

        <Card title="Encapsulation and addressing">
          <Fields>
            <Field label="NAT-T (UDP encapsulation)" value={protocol.natt} />
            <Field label="IPv4 packets" value={scan.ipv4_packets} />
            <Field label="IPv6 packets" value={scan.ipv6_packets} />
            <Field label="ICMP packets" value={scan.icmp_packets} />
            <Field label="Truncated frames" value={scan.truncated_frames} />
            <Field label="Capture format" value={scan.file_format} />
          </Fields>
        </Card>
      </div>

      <Card title="IKE exchanges">
        <Table
          headers={['Exchange', 'Version', 'Status']}
          rows={exchanges.map((item) => [
            show(item.type ?? item.name, 'exchange'),
            show(item.version),
            show(item.status),
          ])}
        />
      </Card>

      <Card title="ESP flows" subtitle="One row per observed SPI direction">
        <Table
          headers={['SPI', 'Source', 'Destination', 'Packets', 'Bytes']}
          rows={flows.map((flow) => [
            show(flow.spi),
            show(flow.src),
            show(flow.dst),
            show(flow.packets),
            show(flow.bytes_total),
          ])}
        />
      </Card>

      <Card title="Perfect forward secrecy">
        <Fields>
          <Field label="PFS status" value={pfs.status} fallback={NOT_VERIFIABLE} />
          <Field
            label="CHILD_SA DH groups"
            value={(pfs.child_sa_dh_groups as string[] | undefined)?.join(', ')}
            fallback="none observed"
          />
          <Field label="Reason" value={pfs.reason} />
        </Fields>
        <NotVerifiableNote />
      </Card>
    </div>
  )
}
