/**
 * Phishing Triage – Shared Layout & Navigation Controller
 * ========================================================
 * Handles sidebar collapse/expand, mobile drawer, global search,
 * and API health polling across all pages.
 */

import { healthCheck } from './api.js';
import { updateApiStatus, initTooltips } from './ui.js';

export function initLayout(activePageName = '') {
  // 1. Sidebar collapse toggle (desktop)
  const sidebar = document.getElementById('sidebar');
  const collapseBtn = document.getElementById('sidebar-collapse-btn');
  const overlay = document.getElementById('sidebar-overlay');
  const mobileToggleBtn = document.getElementById('sidebar-toggle-mobile');

  // Restore collapsed state from localStorage
  const isCollapsed = localStorage.getItem('pt-sidebar-collapsed') === 'true';
  if (sidebar && isCollapsed && window.innerWidth > 768) {
    sidebar.classList.add('collapsed');
  }

  if (collapseBtn && sidebar) {
    collapseBtn.addEventListener('click', () => {
      sidebar.classList.toggle('collapsed');
      const nowCollapsed = sidebar.classList.contains('collapsed');
      localStorage.setItem('pt-sidebar-collapsed', String(nowCollapsed));
    });
  }

  // Mobile drawer toggle
  if (mobileToggleBtn && sidebar) {
    mobileToggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('mobile-open');
      if (overlay) {
        overlay.classList.toggle('active', sidebar.classList.contains('mobile-open'));
      }
    });
  }

  if (overlay && sidebar) {
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('mobile-open');
      overlay.classList.remove('active');
    });
  }

  // Keyboard shortcut Ctrl+[ to toggle sidebar
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === '[') {
      e.preventDefault();
      if (sidebar && window.innerWidth > 768) {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('pt-sidebar-collapsed', String(sidebar.classList.contains('collapsed')));
      }
    }
  });

  // 2. Global Search
  const searchInput = document.getElementById('global-search');
  if (searchInput) {
    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const query = searchInput.value.trim();
        if (query) {
          window.location.href = `history.html?q=${encodeURIComponent(query)}`;
        }
      }
    });
  }

  // 3. Mark active navigation item
  if (activePageName) {
    const navLinks = document.querySelectorAll('.sidebar__link');
    navLinks.forEach((link) => {
      const page = link.getAttribute('data-page');
      if (page === activePageName) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });
  }

  // 4. Check API status
  _checkApiHealth();

  // 5. Initialize tooltips
  initTooltips();
}

async function _checkApiHealth() {
  const indicator = document.getElementById('api-status-indicator');
  const dot = document.getElementById('api-status-dot');
  const label = document.getElementById('api-status-label');

  try {
    const health = await healthCheck();
    const isOnline = health && (health.status === 'ok' || health.status === 'healthy');
    updateApiStatus(isOnline);

    if (indicator) {
      indicator.classList.remove('api-status--checking', 'api-status--offline');
      indicator.classList.toggle('api-status--online', isOnline);
      indicator.classList.toggle('api-status--offline', !isOnline);
    }
    if (dot) {
      dot.classList.toggle('status-online', isOnline);
      dot.classList.toggle('status-offline', !isOnline);
    }
    if (label) {
      label.textContent = isOnline ? 'API Online' : 'API Offline';
    }
  } catch {
    updateApiStatus(false);
    if (indicator) {
      indicator.classList.remove('api-status--checking', 'api-status--online');
      indicator.classList.add('api-status--offline');
    }
    if (dot) {
      dot.classList.remove('status-online');
      dot.classList.add('status-offline');
    }
    if (label) {
      label.textContent = 'API Offline';
    }
  }
}
