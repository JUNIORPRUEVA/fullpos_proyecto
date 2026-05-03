type IdentityLogInput = {
  companyTenantKey?: string | null;
  companyCloudId?: string | null;
  companyRnc?: string | null;
};

function toCleanString(value?: string | null) {
  const v = typeof value === 'string' ? value.trim() : '';
  return v.length > 0 ? v : null;
}

export function redactIdentityValue(
  value?: string | null,
  visibleTail = 6,
): string | null {
  const clean = toCleanString(value);
  if (!clean) return null;
  if (clean.length <= visibleTail) return `***${clean}`;
  return `***${clean.substring(clean.length - visibleTail)}`;
}

export function buildIdentityLog(input: IdentityLogInput) {
  return {
    companyTenantKey: redactIdentityValue(input.companyTenantKey, 10),
    companyCloudId: redactIdentityValue(input.companyCloudId, 8),
    companyRnc: redactIdentityValue(input.companyRnc, 4),
  };
}
