/**
 * Normalize and classify SSH key material from any uploaded/pasted file.
 * Accepts any filename; rejects public keys and PuTTY .ppk with clear errors.
 */

const PRIVATE_BEGIN = /^\s*-{5}BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-{5}\s*$/m
const PUBLIC_LINE = /^\s*(ssh-(?:rsa|ed25519|dss|ecdsa)|ecdsa-sha2-|sk-ssh-)/m

export type KeyCheckResult =
  | { ok: true; secret: string }
  | { ok: false; reason: string }

export function normalizeKeyText(raw: string): string {
  // Strip UTF-8 BOM and normalize newlines for Windows/macOS client exports.
  return raw.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim()
}

export function classifySshKeyMaterial(raw: string, fileName = ''): KeyCheckResult {
  const name = fileName.toLowerCase()
  const secret = normalizeKeyText(raw)

  if (!secret) {
    return { ok: false, reason: 'Key file is empty. Choose the PRIVATE key file from the client.' }
  }
  // PuTTY .ppk is accepted — backend converts to OpenSSH automatically (v2/v3, ed25519).
  const looksLikePpk =
    secret.includes('PuTTY-User-Key-File') ||
    (secret.includes('Private-MAC:') && secret.includes('Public-Lines:') && secret.includes('Private-Lines:'))
  if (name.endsWith('.ppk') || looksLikePpk) {
    if (!looksLikePpk) {
      return { ok: false, reason: 'File name is .ppk but content does not look like a PuTTY private key.' }
    }
    return { ok: true, secret }
  }
  if (name.endsWith('.pub') || PUBLIC_LINE.test(secret.split('\n')[0] || '') || (PUBLIC_LINE.test(secret) && !PRIVATE_BEGIN.test(secret))) {
    return {
      ok: false,
      reason: 'This looks like a PUBLIC key (.pub / ssh-rsa…). Monitoring needs the matching PRIVATE key (id_rsa / ssh-key-….key / .ppk).',
    }
  }
  if (!PRIVATE_BEGIN.test(secret)) {
    return {
      ok: false,
      reason: 'Unrecognized key. Use OpenSSH/PEM private key (-----BEGIN … PRIVATE KEY-----) or PuTTY .ppk. Any filename is fine.',
    }
  }
  if (secret.length < 80) {
    return { ok: false, reason: 'Private key content is too short to be valid.' }
  }
  if (new TextEncoder().encode(secret).length > 64 * 1024) {
    return { ok: false, reason: 'Key file is larger than 64 KB.' }
  }
  return { ok: true, secret }
}

export async function readKeyFromFile(file: File): Promise<KeyCheckResult> {
  if (file.size > 256 * 1024) {
    return { ok: false, reason: 'File is too large (max 256 KB for key material).' }
  }
  try {
    const text = await file.text()
    return classifySshKeyMaterial(text, file.name)
  } catch {
    return { ok: false, reason: 'Could not read that file as text. Choose a plain OpenSSH/PEM private key.' }
  }
}
