/**
 * Phishing Triage – Settings Controller
 * =======================================
 * Manages analyst preferences: API endpoint base, density modes,
 * default defanging, and offline mock-data simulation.
 */

import { API_BASE_URL, USE_MOCK } from './config.js';
import { showToast } from './ui.js';
import { initLayout } from './layout.js';

const STORAGE_KEY = 'pt-settings';

const DEFAULT_SETTINGS = {
  apiUrl: API_BASE_URL || '/api',
  defang: true,
  density: 'comfortable',
  mockMode: USE_MOCK ?? true
};

document.addEventListener('DOMContentLoaded', () => {
  initLayout('settings');
  loadSettings();
  setupEventListeners();
});

/**
 * Retrieve persisted settings or defaults.
 */
export function getSettings() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
    }
  } catch {
    // Ignore parse error
  }
  return { ...DEFAULT_SETTINGS };
}

function loadSettings() {
  const settings = getSettings();

  const apiInput = document.getElementById('api-base-url-input');
  const defangToggle = document.getElementById('defang-toggle');
  const mockToggle = document.getElementById('mock-mode-toggle');
  const comfortableRadio = document.getElementById('density-comfortable');
  const compactRadio = document.getElementById('density-compact');

  if (apiInput) apiInput.value = settings.apiUrl;
  if (defangToggle) defangToggle.checked = Boolean(settings.defang);
  if (mockToggle) mockToggle.checked = Boolean(settings.mockMode);

  if (settings.density === 'compact') {
    if (compactRadio) compactRadio.checked = true;
    document.body.classList.add('density-compact');
  } else {
    if (comfortableRadio) comfortableRadio.checked = true;
    document.body.classList.remove('density-compact');
  }
}

function setupEventListeners() {
  const form = document.getElementById('settings-form');
  const resetBtn = document.getElementById('reset-defaults-btn');

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();

      const apiInput = document.getElementById('api-base-url-input');
      const defangToggle = document.getElementById('defang-toggle');
      const mockToggle = document.getElementById('mock-mode-toggle');
      const compactRadio = document.getElementById('density-compact');

      let apiUrl = (apiInput?.value || '').trim();
      if (!apiUrl) apiUrl = '/api';

      const density = compactRadio?.checked ? 'compact' : 'comfortable';
      const defang = Boolean(defangToggle?.checked);
      const mockMode = Boolean(mockToggle?.checked);

      const newSettings = {
        apiUrl,
        defang,
        density,
        mockMode
      };

      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(newSettings));

        // Apply density class to body
        if (density === 'compact') {
          document.body.classList.add('density-compact');
        } else {
          document.body.classList.remove('density-compact');
        }

        showToast('Settings saved successfully!', 'success');
      } catch (err) {
        showToast(`Failed to persist settings: ${err.message}`, 'error');
      }
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      try {
        localStorage.removeItem(STORAGE_KEY);
        loadSettings();
        showToast('Preferences restored to defaults.', 'info');
      } catch (err) {
        showToast(`Reset error: ${err.message}`, 'error');
      }
    });
  }
}
