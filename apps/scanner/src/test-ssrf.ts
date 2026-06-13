import { assertSafeUrl, isBlockedIp, SsrfError } from './ssrfGuard';

let failures = 0;

function check(name: string, condition: boolean) {
  if (condition) {
    console.log(`  ok   ${name}`);
  } else {
    console.error(`  FAIL ${name}`);
    failures += 1;
  }
}

async function expectRejected(url: string) {
  try {
    await assertSafeUrl(url);
    check(`rejects ${url}`, false);
  } catch (err) {
    check(`rejects ${url}`, err instanceof SsrfError);
  }
}

async function expectAccepted(url: string) {
  try {
    await assertSafeUrl(url);
    check(`accepts ${url}`, true);
  } catch (err) {
    check(`accepts ${url} (${(err as Error).message})`, false);
  }
}

console.log('SSRF guard tests:');

// IP-range unit checks (no network).
check('127.0.0.1 blocked', isBlockedIp('127.0.0.1'));
check('10.1.2.3 blocked', isBlockedIp('10.1.2.3'));
check('172.16.5.5 blocked', isBlockedIp('172.16.5.5'));
check('192.168.0.1 blocked', isBlockedIp('192.168.0.1'));
check('169.254.169.254 blocked', isBlockedIp('169.254.169.254'));
check('::1 blocked', isBlockedIp('::1'));
check('fd00::1 blocked', isBlockedIp('fd00::1'));
check('1.1.1.1 allowed', !isBlockedIp('1.1.1.1'));
check('8.8.8.8 allowed', !isBlockedIp('8.8.8.8'));

await expectRejected('http://localhost');
await expectRejected('http://127.0.0.1');
await expectRejected('http://10.0.0.1');
await expectRejected('http://169.254.169.254/latest/meta-data');
await expectRejected('http://192.168.1.1');
await expectRejected('http://[::1]');
await expectRejected('ftp://example.com');
await expectRejected('http://foo.internal');

// Public IP literal — no DNS/network needed.
await expectAccepted('http://1.1.1.1');
await expectAccepted('https://8.8.8.8/');

if (failures > 0) {
  console.error(`\n${failures} SSRF test(s) failed.`);
  process.exit(1);
}
console.log('\nAll SSRF guard tests passed.');
