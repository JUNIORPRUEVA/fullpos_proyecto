type CloudRateLimitBucket = 'sync' | 'upload' | 'realtime';

type CloudRateLimitPolicy = {
  windowMs: number;
  maxHits: number;
};

type CloudRateLimitInput = {
  bucket: CloudRateLimitBucket;
  key: string;
  nowMs?: number;
};

type CloudRateLimitResult = {
  allowed: boolean;
  retryAfterMs: number;
  remaining: number;
};

const policies: Record<CloudRateLimitBucket, CloudRateLimitPolicy> = {
  // Permite cargas normales por lotes del POS, pero limita abuso extremo.
  sync: { windowMs: 60_000, maxHits: 240 },
  // Uploads de imágenes deben ser más restrictivos.
  upload: { windowMs: 60_000, maxHits: 40 },
  // Reconexiones websocket: tolerante, pero evita tormentas.
  realtime: { windowMs: 60_000, maxHits: 120 },
};

const hitMap = new Map<string, number[]>();

function normalizeKey(value: string) {
  return value.trim().toLowerCase();
}

function mapKey(bucket: CloudRateLimitBucket, key: string) {
  return `${bucket}:${normalizeKey(key)}`;
}

export function consumeCloudRateLimit(
  input: CloudRateLimitInput,
): CloudRateLimitResult {
  const policy = policies[input.bucket];
  const now = input.nowMs ?? Date.now();
  const stateKey = mapKey(input.bucket, input.key);

  const previous = hitMap.get(stateKey) ?? [];
  const windowStart = now - policy.windowMs;
  const kept = previous.filter((ts) => ts >= windowStart);
  kept.push(now);
  hitMap.set(stateKey, kept);

  const allowed = kept.length <= policy.maxHits;
  const oldest = kept.length > 0 ? kept[0] : now;
  const retryAfterMs = allowed
    ? 0
    : Math.max(1, policy.windowMs - (now - oldest));

  return {
    allowed,
    retryAfterMs,
    remaining: Math.max(0, policy.maxHits - kept.length),
  };
}
