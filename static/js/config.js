/**
 * Phishing Triage – Application Configuration
 * =============================================
 * Central configuration constants consumed by every other module.
 */

/** Base URL for all API calls (no trailing slash). */
export const API_BASE_URL = '/api';

/**
 * When `true`, api.js returns data from mock-data.js instead of hitting the
 * real backend.  Flip to `false` once a live API is available.
 */
export const USE_MOCK = true;

/** Maximum upload size in bytes (10 MB). */
export const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 485 760

/** Allowed email file extensions for upload validation. */
export const ALLOWED_EXTENSIONS = ['.eml', '.msg'];

/** Default request timeout in milliseconds. */
export const REQUEST_TIMEOUT_MS = 30_000;

/** Pagination defaults. */
export const DEFAULT_PAGE = 1;
export const DEFAULT_PAGE_SIZE = 10;

/** Simulated network latency range (mock mode only). */
export const MOCK_LATENCY_MIN_MS = 300;
export const MOCK_LATENCY_MAX_MS = 800;
