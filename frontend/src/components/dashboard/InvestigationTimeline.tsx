import React from 'react';
import { Clock, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAnalysisStore } from '../../store/useAnalysisStore';

type TimelineStep = {
  title: string;
  detail: string;
  frame: string;
  page: string;
  color: string;
};

const frameLabel = (value: unknown): string => {
  if (typeof value === 'number' && Number.isFinite(value)) return `Frame ${value}`;
  if (typeof value === 'string' && value.trim()) {
    return value.toLowerCase().startsWith('frame') ? value : `Frame ${value}`;
  }
  return 'Frame evidence unavailable';
};

const firstDefined = (...values: any[]) =>
  values.find((value) => value !== undefined && value !== null && value !== '');

export const InvestigationTimeline: React.FC = () => {
  const navigate = useNavigate();
  const { currentAnalysis } = useAnalysisStore();

  if (!currentAnalysis) return null;

  const stream: any = currentAnalysis.streams?.[0] || {};
  const session: any = currentAnalysis.sessions?.[0] || {};

  const protocol = String(
    firstDefined(session.protocol, stream.protocol, currentAnalysis.protocols_detected?.[0], 'Email')
  ).toUpperCase();

  const starttls: any =
    session.starttls ||
    stream.starttls ||
    (currentAnalysis as any).starttls ||
    {};

  const tls: any =
    session.tls ||
    stream.tls ||
    (currentAnalysis as any).tls ||
    {};

  const clientIp = firstDefined(session.client_ip, stream.client_ip);
  const clientPort = firstDefined(session.client_port, stream.client_port);
  const serverIp = firstDefined(session.server_ip, stream.server_ip);
  const serverPort = firstDefined(session.server_port, stream.server_port);

  const streamId = firstDefined(session.stream_id, stream.stream_id);
  const streamCount = currentAnalysis.streams_count ?? currentAnalysis.streams?.length ?? 0;

  const tlsVersion = firstDefined(
    stream.tls_version,
    session.tls_version,
    tls.version,
    tls.negotiated_version,
    tls.tls_version
  );

  const cipherSuite = firstDefined(
    stream.cipher_suite,
    session.cipher_suite,
    tls.cipher_suite,
    tls.cipher,
    tls.negotiated_cipher
  );

  const advertisedFrame = firstDefined(
    starttls.advertised_frame,
    starttls.capability_frame,
    starttls.offer_frame
  );

  const requestedFrame = firstDefined(
    starttls.requested_frame,
    starttls.request_frame,
    starttls.command_frame
  );

  const acceptedFrame = firstDefined(
    starttls.accepted_frame,
    starttls.response_frame,
    starttls.ready_frame
  );

  const clientHelloFrame = firstDefined(
    tls.client_hello_frame,
    stream.client_hello_frame,
    session.client_hello_frame
  );

  const serverHelloFrame = firstDefined(
    tls.server_hello_frame,
    stream.server_hello_frame,
    session.server_hello_frame
  );

  const starttlsObserved = Boolean(
    stream.starttls_observed ||
    stream.upgrade_successful ||
    session.starttls_observed ||
    starttls.advertised ||
    starttls.requested ||
    starttls.accepted ||
    advertisedFrame ||
    requestedFrame ||
    acceptedFrame
  );

  const upgradeKeyword = protocol === 'POP3' ? 'STLS' : 'STARTTLS';

  const endpointDetail =
    clientIp && serverIp
      ? `${clientIp}${clientPort ? `:${clientPort}` : ''} → ${serverIp}${serverPort ? `:${serverPort}` : ''}`
      : `${streamCount || 1} reconstructed stream${streamCount === 1 ? '' : 's'}${serverPort ? ` (server port ${serverPort})` : ''
      }`;

  const findingsCount = Array.isArray(currentAnalysis.findings)
    ? currentAnalysis.findings.length
    : 0;

  const timelineSteps: TimelineStep[] = [
    {
      title: 'Capture Ingested',
      detail: currentAnalysis.file_size
        ? `${(currentAnalysis.file_size / 1024).toFixed(1)} KB raw PCAP`
        : 'Raw packet capture ingested',
      frame: 'Global',
      page: '/analyze',
      color: '#06b6d4',
    },
    {
      title: `${protocol} Session Reconstructed`,
      detail: endpointDetail,
      frame: streamId ? `Stream ${streamId}` : 'Stream',
      page: '/sessions',
      color: '#22d3ee',
    },
  ];

  if (starttlsObserved) {
    if (advertisedFrame || starttls.advertised) {
      timelineSteps.push({
        title: `${upgradeKeyword} Advertised`,
        detail:
          protocol === 'SMTP'
            ? `${upgradeKeyword} capability observed in server response`
            : `${upgradeKeyword} capability observed`,
        frame: frameLabel(advertisedFrame),
        page: '/packets',
        color: '#34d399',
      });
    }

    if (requestedFrame || starttls.requested) {
      timelineSteps.push({
        title: `${upgradeKeyword} Requested`,
        detail: `Client issued ${upgradeKeyword} command`,
        frame: frameLabel(requestedFrame),
        page: '/packets',
        color: '#34d399',
      });
    }

    if (acceptedFrame || starttls.accepted || stream.upgrade_successful) {
      timelineSteps.push({
        title: `${upgradeKeyword} Accepted`,
        detail: 'Server accepted the TLS upgrade request',
        frame: frameLabel(acceptedFrame),
        page: '/packets',
        color: '#34d399',
      });
    }
  }

  if (clientHelloFrame || tls.client_hello || tlsVersion) {
    timelineSteps.push({
      title: 'TLS ClientHello',
      detail: 'TLS handshake initiation observed',
      frame: frameLabel(clientHelloFrame),
      page: '/packets',
      color: '#818cf8',
    });
  }

  if (serverHelloFrame || tls.server_hello || tlsVersion) {
    timelineSteps.push({
      title: 'TLS ServerHello',
      detail: 'TLS ServerHello observed',
      frame: frameLabel(serverHelloFrame),
      page: '/packets',
      color: '#818cf8',
    });
  }

  if (tlsVersion) {
    timelineSteps.push({
      title: `${tlsVersion} Negotiated`,
      detail: cipherSuite
        ? `${cipherSuite} cipher`
        : 'Negotiated cipher suite unavailable',
      frame:
        serverHelloFrame !== undefined && serverHelloFrame !== null
          ? frameLabel(serverHelloFrame)
          : 'TLS evidence',
      page: '/crypto',
      color: '#34d399',
    });
  }

  if (findingsCount > 0) {
    timelineSteps.push({
      title: 'Findings Generated',
      detail: `${findingsCount} finding${findingsCount === 1 ? '' : 's'} evaluated`,
      frame: 'Analysis',
      page: '/findings',
      color: '#fbbf24',
    });
  }

  timelineSteps.push({
    title: 'Report & Export',
    detail: 'Open the evidence-backed forensic report and export controls',
    frame: 'Report',
    page: '/reports',
    color: '#06b6d4',
  });

  timelineSteps.push({
    title: 'Chain of Custody',
    detail: 'Open cryptographic custody and integrity verification',
    frame: 'SHA-256',
    page: '/custody',
    color: '#10b981',
  });

  return (
    <div className="forensic-panel" style={{ backgroundColor: 'var(--surface-elevated)' }}>
      <div className="forensic-panel-header" style={{ marginBottom: '12px' }}>
        <div>
          <div className="forensic-panel-title">
            <Clock size={13} color="#06b6d4" />
            <span>INVESTIGATION EVIDENCE TIMELINE</span>
          </div>
          <div className="forensic-panel-subtitle">
            Chronological forensic reconstruction anchored to observed PCAP evidence
          </div>
        </div>
        <span className="badge badge-emerald">EVIDENCE-BOUND TIMELINE</span>
      </div>

      <div className="investigation-timeline-grid">
        {timelineSteps.map((step, idx) => (
          <div
            key={`${step.title}-${idx}`}
            onClick={() => navigate(step.page)}
            className="investigation-timeline-card"
            title={`Click to inspect evidence on ${step.page}`}
          >
            <div className="investigation-timeline-card-content">
              <div className="investigation-timeline-card-header">
                <span className="investigation-timeline-step-num">
                  STEP {String(idx + 1).padStart(2, '0')}
                </span>
                <span
                  className="badge badge-cyan investigation-timeline-badge"
                  style={{ color: step.color }}
                  title={step.frame}
                >
                  {step.frame}
                </span>
              </div>

              <div className="investigation-timeline-title" title={step.title}>
                {step.title}
              </div>

              <div className="investigation-timeline-detail">
                {step.detail}
              </div>
            </div>

            <div className="investigation-timeline-footer">
              <span>Inspect</span>
              <ArrowRight size={9} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default InvestigationTimeline;
