import { NextResponse } from 'next/server';
import tls from 'node:tls';
import { assertSafeHostname, isBlockedIp, SsrfError } from '../../../../lib/server/ssrf';
import type { SslResult } from '../../../../lib/tools/ssl';
import type { Check } from '../../../../components/tools/CheckRow';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

interface PeerInfo {
  cert: tls.PeerCertificate;
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorizationError: string | null;
}

/** Open a TLS connection (without rejecting bad certs, so we can report them) and grab the peer cert. */
function inspect(host: string, port: number): Promise<PeerInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout: 10_000 },
      () => {
        const cert = socket.getPeerCertificate(true);
        if (!cert || Object.keys(cert).length === 0) {
          socket.destroy();
          reject(new Error('No certificate presented.'));
          return;
        }
        const info: PeerInfo = {
          cert,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        };
        socket.end();
        resolve(info);
      }
    );
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('Connection timed out.'));
    });
    socket.on('error', (err) => reject(err));
  });
}

function distinguishedName(field: tls.PeerCertificate['subject'] | undefined): string {
  if (!field) return 'Unknown';
  const f = field as Record<string, string>;
  return f.CN || f.O || f.OU || Object.values(f)[0] || 'Unknown';
}

export async function POST(req: Request) {
  let body: { host?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request.' }, { status: 400 });
  }

  const raw = typeof body.host === 'string' ? body.host : '';
  let host: string;
  try {
    host = assertSafeHostname(raw);
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof SsrfError ? e.message : 'Invalid domain.' },
      { status: 400 }
    );
  }

  // Block hosts that are themselves literal private IPs (assertSafeHostname rejects
  // non-domain input, but a guard here keeps intent explicit).
  if (isBlockedIp(host)) {
    return NextResponse.json({ error: 'Private/internal hosts are not allowed.' }, { status: 400 });
  }

  const port = 443;
  let info: PeerInfo;
  try {
    info = await inspect(host, port);
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Connection failed.';
    return NextResponse.json(
      { error: `Could not establish a TLS connection to ${host}:${port} — ${msg}` },
      { status: 502 }
    );
  }

  const { cert } = info;
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const now = Date.now();
  const daysRemaining = Math.floor((validTo.getTime() - now) / 86_400_000);
  const altNames = (cert.subjectaltname ?? '')
    .split(',')
    .map((s) => s.trim().replace(/^DNS:/, ''))
    .filter(Boolean);

  const hostnameError = tls.checkServerIdentity(host, cert);
  const hostnameMatches = !hostnameError;
  // Trust failures other than expiry/hostname (e.g. self-signed, unknown CA).
  const trusted = info.authorized;

  const checks: Check[] = [];

  // Expiry.
  if (daysRemaining < 0) {
    checks.push({
      id: 'expiry',
      label: 'Certificate validity',
      status: 'fail',
      detail: `Expired ${Math.abs(daysRemaining)} day(s) ago, on ${validTo.toUTCString()}.`,
    });
  } else if (daysRemaining <= 14) {
    checks.push({
      id: 'expiry',
      label: 'Certificate validity',
      status: 'warn',
      detail: `Expires in ${daysRemaining} day(s), on ${validTo.toUTCString()}. Renew it soon.`,
    });
  } else {
    checks.push({
      id: 'expiry',
      label: 'Certificate validity',
      status: 'pass',
      detail: `Valid for ${daysRemaining} more day(s), until ${validTo.toUTCString()}.`,
    });
  }

  // Hostname coverage.
  checks.push(
    hostnameMatches
      ? {
          id: 'hostname',
          label: 'Hostname coverage',
          status: 'pass',
          detail: `The certificate is valid for ${host}.`,
        }
      : {
          id: 'hostname',
          label: 'Hostname coverage',
          status: 'fail',
          detail: `The certificate does not cover ${host}. ${hostnameError?.message ?? ''}`.trim(),
        }
  );

  // Chain trust.
  checks.push(
    trusted
      ? {
          id: 'trust',
          label: 'Chain of trust',
          status: 'pass',
          detail: `Issued by ${distinguishedName(cert.issuer)} and trusted by the system CA store.`,
        }
      : {
          id: 'trust',
          label: 'Chain of trust',
          status: 'fail',
          detail: `The chain is not trusted${info.authorizationError ? ` (${info.authorizationError})` : ''}. This is shown to every visitor as a security warning.`,
        }
  );

  // Protocol.
  const proto = info.protocol ?? '';
  const legacyProto = proto === 'TLSv1' || proto === 'TLSv1.1' || proto === 'SSLv3';
  checks.push({
    id: 'protocol',
    label: 'TLS protocol',
    status: proto === 'TLSv1.3' ? 'pass' : legacyProto ? 'fail' : proto ? 'warn' : 'info',
    detail: proto
      ? legacyProto
        ? `Negotiated ${proto}, which is deprecated and insecure. Disable everything below TLS 1.2.`
        : proto === 'TLSv1.3'
          ? 'Negotiated TLS 1.3 — the current best practice.'
          : `Negotiated ${proto}. Acceptable, but enabling TLS 1.3 is recommended.`
      : 'Could not determine the negotiated protocol.',
  });

  if (info.cipher) {
    checks.push({ id: 'cipher', label: 'Cipher suite', status: 'info', detail: info.cipher });
  }

  // Grade.
  let grade: SslResult['grade'];
  if (daysRemaining < 0 || !hostnameMatches || !trusted) grade = 'F';
  else if (legacyProto) grade = 'D';
  else if (daysRemaining <= 14) grade = 'C';
  else if (proto !== 'TLSv1.3') grade = 'B';
  else grade = 'A';

  const summary =
    grade === 'A'
      ? 'Valid certificate, trusted chain and modern TLS.'
      : grade === 'F'
        ? 'This certificate would trigger a browser security warning.'
        : 'The certificate works but has room for improvement.';

  const result: SslResult = {
    host,
    port,
    protocol: info.protocol,
    cipher: info.cipher,
    subject: distinguishedName(cert.subject),
    altNames,
    issuer: distinguishedName(cert.issuer),
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    daysRemaining,
    hostnameMatches,
    trusted,
    authorizationError: info.authorizationError,
    grade,
    summary,
    checks,
  };

  return NextResponse.json(result);
}
