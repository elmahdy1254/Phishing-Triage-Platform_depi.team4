/**
 * Phishing Triage – Utility Functions
 * =====================================
 * Pure helpers with zero side-effects (except clipboard / toast).
 */

// ---------------------------------------------------------------------------
// URL defanging / refanging
// ---------------------------------------------------------------------------

/**
 * Defang a URL for safe display.
 * `https://evil.com/path` → `hxxps://evil[.]com/path`
 *
 * @param {string} url
 * @returns {string}
 */
export function defangUrl(url) {
  if (!url) return '';
  return url
    .replace(/^https?/i, (m) => m.replace(/t/gi, 'x').replace(/T/gi, 'X'))
    .replace(/\./g, '[.]');
}

/**
 * Reverse a defanged URL back to its original form.
 *
 * @param {string} url
 * @returns {string}
 */
export function refangUrl(url) {
  if (!url) return '';
  return url
    .replace(/hxxps?/i, (m) =>
      m.replace(/xx/i, 'tt')
    )
    .replace(/\[\.\]/g, '.');
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

/**
 * Copy `text` to the clipboard and show a brief toast.
 *
 * @param {string} text
 * @returns {Promise<void>}
 */
export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    // Lazily import showToast to avoid circular deps at module-eval time.
    const { showToast } = await import('./ui.js');
    showToast('Copied to clipboard', 'success');
  } catch {
    // Fallback for older browsers / insecure contexts
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      const { showToast } = await import('./ui.js');
      showToast('Copied to clipboard', 'success');
    } catch {
      const { showToast } = await import('./ui.js');
      showToast('Failed to copy', 'error');
    } finally {
      document.body.removeChild(textarea);
    }
  }
}

// ---------------------------------------------------------------------------
// Date / time formatting
// ---------------------------------------------------------------------------

/**
 * Format an ISO-8601 string as a human-readable local date-time.
 * Example: "Nov 19, 2026, 12:32 PM"
 *
 * @param {string} isoString
 * @returns {string}
 */
export function formatDate(isoString) {
  if (!isoString) return '—';
  try {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true
    }).format(new Date(isoString));
  } catch {
    return isoString;
  }
}

/**
 * Return a relative-time string such as "2 hours ago".
 *
 * @param {string} isoString
 * @returns {string}
 */
export function formatRelativeTime(isoString) {
  if (!isoString) return '—';

  const now = Date.now();
  const then = new Date(isoString).getTime();
  const diffMs = now - then;

  if (Number.isNaN(diffMs)) return isoString;

  const seconds = Math.floor(Math.abs(diffMs) / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  const weeks = Math.floor(days / 7);
  const months = Math.floor(days / 30);

  const isFuture = diffMs < 0;
  let value, unit;

  if (seconds < 60) {
    value = seconds;
    unit = 'second';
  } else if (minutes < 60) {
    value = minutes;
    unit = 'minute';
  } else if (hours < 24) {
    value = hours;
    unit = 'hour';
  } else if (days < 7) {
    value = days;
    unit = 'day';
  } else if (weeks < 5) {
    value = weeks;
    unit = 'week';
  } else {
    value = months;
    unit = 'month';
  }

  if (typeof Intl !== 'undefined' && Intl.RelativeTimeFormat) {
    const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
    return rtf.format(isFuture ? value : -value, unit);
  }

  const plural = value !== 1 ? 's' : '';
  return isFuture
    ? `in ${value} ${unit}${plural}`
    : `${value} ${unit}${plural} ago`;
}

// ---------------------------------------------------------------------------
// File size
// ---------------------------------------------------------------------------

/**
 * Format bytes as a human-readable string.
 *
 * @param {number} bytes
 * @returns {string}
 */
export function formatFileSize(bytes) {
  if (bytes == null || bytes < 0) return '—';
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const size = bytes / Math.pow(1024, i);

  return `${size % 1 === 0 ? size : size.toFixed(1)} ${units[i]}`;
}

// ---------------------------------------------------------------------------
// Security: HTML escaping
// ---------------------------------------------------------------------------

const HTML_ESCAPE_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
};

/**
 * Escape HTML entities so a string can be safely inserted into the DOM
 * via `textContent` or templated into an attribute.
 *
 * @param {string} str
 * @returns {string}
 */
export function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, (ch) => HTML_ESCAPE_MAP[ch]);
}

// ---------------------------------------------------------------------------
// Verdict / auth helpers
// ---------------------------------------------------------------------------

/**
 * Map a verdict string to its semantic CSS class.
 *
 * @param {string} verdict  "clean" | "suspicious" | "malicious" | "unknown"
 * @returns {string}
 */
export function getVerdictClass(verdict) {
  const map = {
    clean: 'verdict-safe',
    suspicious: 'verdict-warning',
    malicious: 'verdict-danger',
    unknown: 'verdict-info'
  };
  return map[verdict] || 'verdict-info';
}

/**
 * Map a verdict string to a Bootstrap Icon class.
 *
 * @param {string} verdict
 * @returns {string}
 */
export function getVerdictIcon(verdict) {
  const map = {
    clean: 'bi-check-circle-fill',
    suspicious: 'bi-exclamation-triangle-fill',
    malicious: 'bi-x-octagon-fill',
    unknown: 'bi-question-circle-fill'
  };
  return map[verdict] || 'bi-question-circle-fill';
}

/**
 * Map an authentication status to a CSS class.
 *
 * @param {string} status  "pass" | "fail" | "softfail" | "neutral" | "none"
 * @returns {string}
 */
export function getAuthStatusClass(status) {
  const map = {
    pass: 'auth-pass',
    fail: 'auth-fail',
    softfail: 'auth-softfail',
    neutral: 'auth-neutral',
    none: 'auth-none'
  };
  return map[status] || 'auth-none';
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/**
 * Truncate a string to `maxLen` characters, adding an ellipsis when cut.
 *
 * @param {string} str
 * @param {number} maxLen
 * @returns {string}
 */
export function truncate(str, maxLen = 80) {
  if (!str) return '';
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 1).trimEnd() + '…';
}

/**
 * Generate a random short alphanumeric ID (8 chars).
 *
 * @returns {string}
 */
export function generateId() {
  return Math.random().toString(36).slice(2, 10);
}

// ---------------------------------------------------------------------------
// Debounce
// ---------------------------------------------------------------------------

/**
 * Classic debounce: return a wrapper that delays `fn` until `ms` milliseconds
 * of inactivity.
 *
 * @param {Function} fn
 * @param {number} ms
 * @returns {Function}
 */
export function debounce(fn, ms = 300) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}

// ---------------------------------------------------------------------------
// IOC extraction
// ---------------------------------------------------------------------------

/**
 * Collect all Indicators of Compromise (IOCs) from an analysis object.
 * Returns a flat array of `{ type, value }` objects.
 *
 * @param {object} analysis  Full analysis object matching the JSON contract.
 * @returns {{ type: string, value: string }[]}
 */
export function collectIOCs(analysis) {
  if (!analysis) return [];

  const iocs = [];

  // Hashes from attachments
  if (Array.isArray(analysis.attachments)) {
    for (const att of analysis.attachments) {
      if (att.md5) iocs.push({ type: 'MD5', value: att.md5 });
      if (att.sha256) iocs.push({ type: 'SHA256', value: att.sha256 });
    }
  }

  // Domains from URLs
  if (Array.isArray(analysis.urls)) {
    const seenDomains = new Set();
    for (const u of analysis.urls) {
      if (u.domain && !seenDomains.has(u.domain)) {
        seenDomains.add(u.domain);
        iocs.push({ type: 'Domain', value: u.domain });
      }
    }
  }

  // IPs from routing
  if (Array.isArray(analysis.routing)) {
    const seenIPs = new Set();
    for (const hop of analysis.routing) {
      if (hop.ip && !seenIPs.has(hop.ip)) {
        seenIPs.add(hop.ip);
        iocs.push({ type: 'IP', value: hop.ip });
      }
    }
  }

  // Sender address
  if (analysis.envelope?.from) {
    iocs.push({ type: 'Email', value: analysis.envelope.from });
  }

  return iocs;
}
