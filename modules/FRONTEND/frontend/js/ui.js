/**
 * Phishing Triage – UI Helpers
 * ==============================
 * Reusable DOM helpers for toasts, modals, skeletons, error banners,
 * empty states, tooltips, and the API-status indicator.
 *
 * Every function that injects content uses `textContent` or safe DOM APIs –
 * never `innerHTML` with user / email data.
 */

// ---------------------------------------------------------------------------
// Internal: ensure a toast container exists
// ---------------------------------------------------------------------------
function _getToastContainer() {
  let container = document.getElementById('pt-toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'pt-toast-container';
    container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    container.setAttribute('aria-live', 'polite');
    container.setAttribute('aria-atomic', 'true');
    document.body.appendChild(container);
  }
  return container;
}

// ---------------------------------------------------------------------------
// showToast
// ---------------------------------------------------------------------------

/** Map of toast types to Bootstrap text/bg utilities & icons. */
const TOAST_CONFIG = {
  success: { icon: 'bi-check-circle-fill', cssClass: 'toast-success' },
  error: { icon: 'bi-x-octagon-fill', cssClass: 'toast-error' },
  warning: { icon: 'bi-exclamation-triangle-fill', cssClass: 'toast-warning' },
  info: { icon: 'bi-info-circle-fill', cssClass: 'toast-info' }
};

/**
 * Display a lightweight Bootstrap toast notification.
 *
 * @param {string} message  Text to display.
 * @param {"success"|"error"|"warning"|"info"} [type="info"]
 * @param {number} [duration=3500]  Auto-hide delay (ms).
 */
export function showToast(message, type = 'info', duration = 3500) {
  const container = _getToastContainer();
  const cfg = TOAST_CONFIG[type] || TOAST_CONFIG.info;

  // Build toast element (no innerHTML with untrusted data)
  const toast = document.createElement('div');
  toast.className = `toast align-items-center border-0 ${cfg.cssClass}`;
  toast.setAttribute('role', 'status');
  toast.setAttribute('aria-live', 'polite');
  toast.setAttribute('aria-atomic', 'true');

  const flexWrap = document.createElement('div');
  flexWrap.className = 'd-flex';

  const body = document.createElement('div');
  body.className = 'toast-body d-flex align-items-center gap-2';

  const icon = document.createElement('i');
  icon.className = `bi ${cfg.icon}`;
  icon.setAttribute('aria-hidden', 'true');

  const text = document.createElement('span');
  text.textContent = message;

  body.appendChild(icon);
  body.appendChild(text);

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'btn-close btn-close-white me-2 m-auto';
  closeBtn.setAttribute('data-bs-dismiss', 'toast');
  closeBtn.setAttribute('aria-label', 'Close');

  flexWrap.appendChild(body);
  flexWrap.appendChild(closeBtn);
  toast.appendChild(flexWrap);

  container.appendChild(toast);

  // Bootstrap Toast API (expects Bootstrap 5.3 loaded)
  /* global bootstrap */
  const bsToast = new bootstrap.Toast(toast, { delay: duration });
  bsToast.show();

  // Clean up after hiding
  toast.addEventListener('hidden.bs.toast', () => toast.remove(), { once: true });
}

// ---------------------------------------------------------------------------
// showConfirmModal
// ---------------------------------------------------------------------------

/**
 * Display a confirmation modal and invoke `onConfirm` if the user accepts.
 *
 * @param {string} title      Modal title.
 * @param {string} message    Modal body text.
 * @param {Function} onConfirm  Called when user clicks "Confirm".
 */
export function showConfirmModal(title, message, onConfirm) {
  // Re-use a single modal element to avoid leaking DOM nodes
  let modalEl = document.getElementById('pt-confirm-modal');
  if (!modalEl) {
    modalEl = document.createElement('div');
    modalEl.id = 'pt-confirm-modal';
    modalEl.className = 'modal fade';
    modalEl.tabIndex = -1;
    modalEl.setAttribute('aria-hidden', 'true');
    modalEl.setAttribute('aria-labelledby', 'pt-confirm-modal-title');

    modalEl.innerHTML = `
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content bg-surface">
          <div class="modal-header border-bottom-subtle">
            <h5 class="modal-title" id="pt-confirm-modal-title"></h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">
            <p id="pt-confirm-modal-body"></p>
          </div>
          <div class="modal-footer border-top-subtle">
            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-primary" id="pt-confirm-modal-ok">Confirm</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modalEl);
  }

  // Set text safely
  const titleEl = modalEl.querySelector('#pt-confirm-modal-title');
  const bodyEl = modalEl.querySelector('#pt-confirm-modal-body');
  const okBtn = modalEl.querySelector('#pt-confirm-modal-ok');

  titleEl.textContent = title;
  bodyEl.textContent = message;

  // Wire up confirm action (replace previous handler)
  const newOkBtn = okBtn.cloneNode(true);
  okBtn.parentNode.replaceChild(newOkBtn, okBtn);

  newOkBtn.addEventListener(
    'click',
    () => {
      const modalInstance = bootstrap.Modal.getInstance(modalEl);
      if (modalInstance) modalInstance.hide();
      if (typeof onConfirm === 'function') onConfirm();
    },
    { once: true }
  );

  const modal = new bootstrap.Modal(modalEl);
  modal.show();
}

// ---------------------------------------------------------------------------
// Skeleton loaders
// ---------------------------------------------------------------------------

const SKELETON_CLASS = 'pt-skeleton';

/**
 * Render placeholder skeleton loaders inside `container`.
 *
 * @param {HTMLElement} container  DOM element to fill with skeletons.
 * @param {number} [rows=3]  Number of skeleton rows.
 */
export function showLoadingSkeleton(container, rows = 3) {
  if (!container) return;

  // Clear any previous content
  container.innerHTML = '';

  const wrapper = document.createElement('div');
  wrapper.className = SKELETON_CLASS;
  wrapper.setAttribute('aria-busy', 'true');
  wrapper.setAttribute('aria-label', 'Loading content');

  for (let i = 0; i < rows; i++) {
    const card = document.createElement('div');
    card.className = 'skeleton-card mb-3';

    const titleBar = document.createElement('div');
    titleBar.className = 'skeleton-line skeleton-title';
    card.appendChild(titleBar);

    for (let j = 0; j < 2; j++) {
      const line = document.createElement('div');
      line.className = 'skeleton-line';
      if (j === 1) line.classList.add('skeleton-short');
      card.appendChild(line);
    }

    wrapper.appendChild(card);
  }

  container.appendChild(wrapper);
}

/**
 * Remove skeleton loaders from `container`.
 *
 * @param {HTMLElement} container
 */
export function hideLoadingSkeleton(container) {
  if (!container) return;
  const skeleton = container.querySelector(`.${SKELETON_CLASS}`);
  if (skeleton) skeleton.remove();
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

/**
 * Render an empty-state placeholder inside `container`.
 *
 * @param {HTMLElement} container
 * @param {string} [message="No data available"]
 * @param {string} [icon="bi-inbox"]  Bootstrap Icon class.
 */
export function showEmptyState(
  container,
  message = 'No data available',
  icon = 'bi-inbox'
) {
  if (!container) return;
  container.innerHTML = '';

  const wrapper = document.createElement('div');
  wrapper.className = 'pt-empty-state text-center py-5';

  const iconEl = document.createElement('i');
  iconEl.className = `bi ${icon} pt-empty-icon`;
  iconEl.setAttribute('aria-hidden', 'true');

  const msg = document.createElement('p');
  msg.className = 'pt-empty-text mt-3';
  msg.textContent = message;

  wrapper.appendChild(iconEl);
  wrapper.appendChild(msg);
  container.appendChild(wrapper);
}

// ---------------------------------------------------------------------------
// Error banner
// ---------------------------------------------------------------------------

const ERROR_BANNER_CLASS = 'pt-error-banner';

/**
 * Display an inline error banner with an optional retry button.
 *
 * @param {HTMLElement} container
 * @param {string} message
 * @param {Function|null} [retryFn=null]  If provided, renders a "Retry" button.
 */
export function showErrorBanner(container, message, retryFn = null) {
  if (!container) return;

  // Remove any existing error banner first
  hideErrorBanner(container);

  const banner = document.createElement('div');
  banner.className = `${ERROR_BANNER_CLASS} alert d-flex align-items-center gap-2`;
  banner.setAttribute('role', 'alert');

  const icon = document.createElement('i');
  icon.className = 'bi bi-exclamation-triangle-fill';
  icon.setAttribute('aria-hidden', 'true');

  const text = document.createElement('span');
  text.className = 'flex-grow-1';
  text.textContent = message;

  banner.appendChild(icon);
  banner.appendChild(text);

  if (typeof retryFn === 'function') {
    const retryBtn = document.createElement('button');
    retryBtn.type = 'button';
    retryBtn.className = 'btn btn-sm btn-outline-warning';
    retryBtn.textContent = 'Retry';
    retryBtn.setAttribute('aria-label', 'Retry the failed operation');
    retryBtn.addEventListener('click', () => {
      hideErrorBanner(container);
      retryFn();
    });
    banner.appendChild(retryBtn);
  }

  // Prepend so it appears at the top
  container.prepend(banner);
}

/**
 * Remove any error banner from `container`.
 *
 * @param {HTMLElement} container
 */
export function hideErrorBanner(container) {
  if (!container) return;
  const banner = container.querySelector(`.${ERROR_BANNER_CLASS}`);
  if (banner) banner.remove();
}

// ---------------------------------------------------------------------------
// Tooltips
// ---------------------------------------------------------------------------

/**
 * Initialise (or re-initialise) Bootstrap tooltips on elements with
 * `data-bs-toggle="tooltip"`.
 */
export function initTooltips() {
  const els = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  els.forEach((el) => {
    // Dispose existing to avoid duplicates
    const existing = bootstrap.Tooltip.getInstance(el);
    if (existing) existing.dispose();
    new bootstrap.Tooltip(el);
  });
}

// ---------------------------------------------------------------------------
// API status indicator
// ---------------------------------------------------------------------------

/**
 * Update the visual API-health indicator in the top bar.
 * Expects an element with id `api-status-indicator` in the DOM.
 *
 * @param {boolean} isOnline
 */
export function updateApiStatus(isOnline) {
  const dot = document.getElementById('api-status-dot');
  const label = document.getElementById('api-status-label');

  if (dot) {
    dot.classList.toggle('status-online', isOnline);
    dot.classList.toggle('status-offline', !isOnline);
    dot.setAttribute('aria-label', isOnline ? 'API online' : 'API offline');
  }

  if (label) {
    label.textContent = isOnline ? 'API Online' : 'API Offline';
  }
}
