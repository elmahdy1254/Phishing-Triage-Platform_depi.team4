/**
 * Phishing Triage – API Client
 * ==============================
 * Single-source-of-truth for ALL HTTP communication.
 * No other module should use `fetch` directly.
 *
 * When `USE_MOCK` is enabled, every endpoint returns realistic data from
 * mock-data.js with a simulated network delay (300–800 ms).
 */

import {
  API_BASE_URL,
  USE_MOCK,
  MAX_FILE_SIZE,
  ALLOWED_EXTENSIONS,
  REQUEST_TIMEOUT_MS,
  MOCK_LATENCY_MIN_MS,
  MOCK_LATENCY_MAX_MS
} from './config.js';

import {
  MOCK_ANALYSES,
  MOCK_STATS,
  MOCK_HEALTH,
  getMockAnalysisById,
  getMockAnalysesList
} from './mock-data.js';

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

/**
 * Structured API error with status code and human-readable message.
 */
export class ApiError extends Error {
  /**
   * @param {number} status   HTTP status code (or 0 for network errors).
   * @param {string} message  Human-readable description.
   */
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Sleep for a random duration between `min` and `max` ms.
 * Used in mock mode to simulate network latency.
 */
function _simulateLatency() {
  const ms =
    Math.floor(Math.random() * (MOCK_LATENCY_MAX_MS - MOCK_LATENCY_MIN_MS)) +
    MOCK_LATENCY_MIN_MS;
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Perform a fetch request with timeout support.
 *
 * @param {string} url
 * @param {RequestInit} [options={}]
 * @returns {Promise<Response>}
 */
async function _fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    return response;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new ApiError(0, 'Request timed out. Please try again.');
    }
    throw new ApiError(0, `Network error: ${err.message}`);
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Process a Response and return parsed JSON or throw an ApiError.
 *
 * @param {Response} response
 * @returns {Promise<any>}
 */
async function _handleResponse(response) {
  if (!response.ok) {
    let message = `Server error (${response.status})`;
    try {
      const body = await response.json();
      if (body.message) message = body.message;
      if (body.error) message = body.error;
    } catch {
      // non-JSON error body – keep default message
    }
    throw new ApiError(response.status, message);
  }

  // 204 No Content
  if (response.status === 204) return null;

  return response.json();
}

/**
 * Build a full URL from a path and optional query params.
 *
 * @param {string} path
 * @param {Record<string, any>} [params]
 * @returns {string}
 */
function _buildUrl(path, params) {
  const url = new URL(`${API_BASE_URL}${path}`, window.location.origin);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.toString();
}

/**
 * Client-side file validation before upload.
 *
 * @param {File} file
 * @throws {ApiError} if validation fails.
 */
function _validateFile(file) {
  if (!file) {
    throw new ApiError(400, 'No file selected.');
  }

  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    throw new ApiError(
      400,
      `Invalid file type "${ext}". Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`
    );
  }

  if (file.size > MAX_FILE_SIZE) {
    const maxMB = (MAX_FILE_SIZE / (1024 * 1024)).toFixed(0);
    throw new ApiError(400, `File exceeds the ${maxMB} MB size limit.`);
  }
}

// ---------------------------------------------------------------------------
// Deep-clone helper (avoids shared references to mock objects)
// ---------------------------------------------------------------------------
function _clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/**
 * Upload and analyse an email file.
 *
 * POST /api/analyze  (multipart/form-data, field "file")
 *
 * @param {File} file  The .eml or .msg file to analyse.
 * @returns {Promise<object>}  The full analysis JSON.
 */
export async function analyze(file) {
  _validateFile(file);

  if (USE_MOCK) {
    await _simulateLatency();
    // Return the high-risk mock as the "newly analysed" result
    const mockResult = _clone(MOCK_ANALYSES[0]);
    mockResult.id = crypto.randomUUID
      ? crypto.randomUUID().slice(0, 6)
      : Math.random().toString(36).slice(2, 8);
    mockResult.filename = file.name;
    mockResult.analyzed_at = new Date().toISOString();
    return mockResult;
  }

  const formData = new FormData();
  formData.append('file', file);

  const response = await _fetchWithTimeout(_buildUrl('/analyze'), {
    method: 'POST',
    body: formData
  });

  return _handleResponse(response);
}

/**
 * List analyses with optional filters and pagination.
 *
 * GET /api/analyses?page=&limit=&verdict=&q=
 *
 * @param {{ page?: number, limit?: number, verdict?: string, q?: string }} [params={}]
 * @returns {Promise<{ items: object[], total: number }>}
 */
export async function getAnalyses(params = {}) {
  if (USE_MOCK) {
    await _simulateLatency();
    return _clone(getMockAnalysesList(params));
  }

  const response = await _fetchWithTimeout(
    _buildUrl('/analyses', params)
  );
  return _handleResponse(response);
}

/**
 * Fetch a single analysis by ID.
 *
 * GET /api/analyses/{id}
 *
 * @param {string} id  Analysis ID.
 * @returns {Promise<object>}  Full analysis JSON.
 */
export async function getAnalysis(id) {
  if (!id) throw new ApiError(400, 'Analysis ID is required.');

  if (USE_MOCK) {
    await _simulateLatency();
    const analysis = getMockAnalysisById(id);
    if (!analysis) {
      throw new ApiError(404, `Analysis "${id}" not found.`);
    }
    return _clone(analysis);
  }

  const response = await _fetchWithTimeout(
    _buildUrl(`/analyses/${encodeURIComponent(id)}`)
  );
  return _handleResponse(response);
}

/**
 * Delete an analysis.
 *
 * DELETE /api/analyses/{id}
 *
 * @param {string} id  Analysis ID.
 * @returns {Promise<null>}
 */
export async function deleteAnalysis(id) {
  if (!id) throw new ApiError(400, 'Analysis ID is required.');

  if (USE_MOCK) {
    await _simulateLatency();
    const idx = MOCK_ANALYSES.findIndex((a) => a.id === id);
    if (idx === -1) {
      throw new ApiError(404, `Analysis "${id}" not found.`);
    }
    // Don't actually mutate mock data – just acknowledge
    return null;
  }

  const response = await _fetchWithTimeout(
    _buildUrl(`/analyses/${encodeURIComponent(id)}`),
    { method: 'DELETE' }
  );
  return _handleResponse(response);
}

/**
 * Export an analysis in the given format.
 *
 * GET /api/analyses/{id}/export?format=json|csv|pdf
 *
 * In live mode this triggers a file download.  In mock mode it returns a
 * JSON representation as a Blob.
 *
 * @param {string} id
 * @param {"json"|"csv"|"pdf"} [format="json"]
 * @returns {Promise<Blob>}
 */
export async function exportAnalysis(id, format = 'json') {
  if (!id) throw new ApiError(400, 'Analysis ID is required.');

  const validFormats = ['json', 'csv', 'pdf'];
  if (!validFormats.includes(format)) {
    throw new ApiError(400, `Invalid format "${format}". Use: ${validFormats.join(', ')}`);
  }

  if (USE_MOCK) {
    await _simulateLatency();
    const analysis = getMockAnalysisById(id);
    if (!analysis) {
      throw new ApiError(404, `Analysis "${id}" not found.`);
    }

    if (format === 'json') {
      const json = JSON.stringify(analysis, null, 2);
      return new Blob([json], { type: 'application/json' });
    }

    if (format === 'csv') {
      const csv = _analysisToCsv(analysis);
      return new Blob([csv], { type: 'text/csv' });
    }

    // PDF – return a placeholder text blob in mock mode
    const placeholder = `[PDF Report — ${analysis.filename}]\n\nThis is a mock PDF export.\nRisk Score: ${analysis.risk.score}\nVerdict: ${analysis.risk.verdict}`;
    return new Blob([placeholder], { type: 'application/pdf' });
  }

  const response = await _fetchWithTimeout(
    _buildUrl(`/analyses/${encodeURIComponent(id)}/export`, { format })
  );

  if (!response.ok) {
    throw new ApiError(response.status, `Export failed (${response.status})`);
  }

  return response.blob();
}

/**
 * Quick CSV serialiser for mock export.
 * @param {object} analysis
 * @returns {string}
 */
function _analysisToCsv(analysis) {
  const rows = [
    ['Field', 'Value'],
    ['ID', analysis.id],
    ['Filename', analysis.filename],
    ['Analyzed At', analysis.analyzed_at],
    ['Risk Score', analysis.risk.score],
    ['Verdict', analysis.risk.verdict],
    ['From', analysis.envelope.from],
    ['To', analysis.envelope.to],
    ['Subject', analysis.envelope.subject],
    ['SPF', analysis.authentication.spf],
    ['DKIM', analysis.authentication.dkim],
    ['DMARC', analysis.authentication.dmarc]
  ];

  if (analysis.urls) {
    analysis.urls.forEach((u, i) => {
      rows.push([`URL_${i + 1}`, u.url]);
      rows.push([`URL_${i + 1}_Verdict`, u.verdict]);
      rows.push([`URL_${i + 1}_Detections`, `${u.detections}/${u.total_engines}`]);
    });
  }

  if (analysis.attachments) {
    analysis.attachments.forEach((a, i) => {
      rows.push([`Attachment_${i + 1}`, a.filename]);
      rows.push([`Attachment_${i + 1}_MD5`, a.md5]);
      rows.push([`Attachment_${i + 1}_SHA256`, a.sha256]);
      rows.push([`Attachment_${i + 1}_Verdict`, a.verdict]);
    });
  }

  return rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
}

/**
 * Fetch dashboard statistics and chart data.
 *
 * GET /api/stats
 *
 * @returns {Promise<object>}
 */
export async function getStats() {
  if (USE_MOCK) {
    await _simulateLatency();
    return _clone(MOCK_STATS);
  }

  const response = await _fetchWithTimeout(_buildUrl('/stats'));
  return _handleResponse(response);
}

/**
 * Check API health / connectivity.
 *
 * GET /api/health
 *
 * @returns {Promise<object>}  Health payload with `status`, `version`, etc.
 */
export async function healthCheck() {
  if (USE_MOCK) {
    await _simulateLatency();
    return _clone(MOCK_HEALTH);
  }

  const response = await _fetchWithTimeout(_buildUrl('/health'));
  return _handleResponse(response);
}
