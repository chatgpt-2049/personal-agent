// PKCS#10 using RFC 8410 Ed25519 AlgorithmIdentifiers (parameters absent).
function join(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function der(tag: number, contents: Uint8Array): Uint8Array<ArrayBuffer> {
  const length: number[] = [];
  let n = contents.length;
  do {
    length.unshift(n & 255);
    n >>>= 8;
  } while (n);
  return join(new Uint8Array([tag]), new Uint8Array(contents.length < 128 ? [contents.length] : [128 + length.length, ...length]), contents);
}

const sequence = (...parts: Uint8Array[]) => der(0x30, join(...parts));
const algorithm = () => sequence(der(0x06, new Uint8Array([0x2b, 0x65, 0x70])));

export async function createEd25519Csr(pem: string, commonName: string): Promise<string> {
  const cn = commonName.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(cn)) {
    throw new Error("Enter an Ethereum address: 0x followed by 40 hex characters.");
  }
  if (pem.length > 16384) throw new Error("Key file is too large.");
  const match = /^\s*-----BEGIN PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----\s*$/.exec(pem);
  if (!match?.[1]) throw new Error("Select an unencrypted Ed25519 PKCS#8 PEM private key.");
  const bytes = Uint8Array.from(atob(match[1].replace(/\s/g, "")), c => c.charCodeAt(0));
  try {
    // Temporary extractability is necessary to derive the public key through JWK.
    // The key never leaves browser memory and is not persisted.
    const key = await crypto.subtle.importKey("pkcs8", bytes, "Ed25519", true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    if (!jwk.x) throw new Error("Missing public key.");
    const publicKey = Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/").padEnd(44, "=")), c => c.charCodeAt(0));
    // Do not retain the exported private scalar.
    delete jwk.d;
    const subject = sequence(der(0x31, sequence(
      der(0x06, new Uint8Array([0x55, 0x04, 0x03])),
      der(0x0c, new TextEncoder().encode(cn)),
    )));
    const info = sequence(
      der(0x02, new Uint8Array([0])),
      subject,
      sequence(algorithm(), der(0x03, join(new Uint8Array([0]), publicKey))),
      der(0xa0, new Uint8Array()),
    );
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", key, info));
    const csr = sequence(info, algorithm(), der(0x03, join(new Uint8Array([0]), signature)));
    const base64 = btoa(String.fromCharCode(...csr));
    return `-----BEGIN CERTIFICATE REQUEST-----\n${base64.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE REQUEST-----\n`;
  }
  finally {
    bytes.fill(0);
  }
}
