/**
 * Phishing Triage – History & Archive Controller
 * ================================================
 * Handles paginated archive browsing, text search, verdict filtering,
 * client-side column sorting, and deletion management.
 */

import { getAnalyses, deleteAnalysis } from './api.js';
import {
  formatDate,
  formatRelativeTime,
  truncate,
  debounce
} from './utils.js';
import { showToast, showConfirmModal, showErrorBanner, showEmptyState } from './ui.js';
import { initLayout } from './layout.js';

let state = {
  page: 1,
  limit: 20,
  verdict: '',
  q: '',
  sortField: 'date',
  sortAsc: false,
  total: 0,
  items: []
};

document.addEventListener('DOMContentLoaded', () => {
  initLayout('history');
  readUrlParams();
  setupEventListeners();
  loadHistoryData();
});

function readUrlParams() {
  const params = new URLSearchParams(window.location.search);
  if (params.has('q')) state.q = params.get('q');
  if (params.has('verdict')) state.verdict = params.get('verdict');
  if (params.has('page')) state.page = Math.max(1, parseInt(params.get('page'), 10) || 1);
  if (params.has('limit')) state.limit = Math.max(1, parseInt(params.get('limit'), 10) || 20);

  // Sync inputs
  const searchInput = document.getElementById('history-search-input');
  const verdictFilter = document.getElementById('history-verdict-filter');
  const limitSelect = document.getElementById('history-limit-select');

  if (searchInput && state.q) searchInput.value = state.q;
  if (verdictFilter && state.verdict) verdictFilter.value = state.verdict;
  if (limitSelect && state.limit) limitSelect.value = String(state.limit);
}

function updateUrlParams() {
  const url = new URL(window.location.href);
  if (state.q) url.searchParams.set('q', state.q);
  else url.searchParams.delete('q');

  if (state.verdict) url.searchParams.set('verdict', state.verdict);
  else url.searchParams.delete('verdict');

  if (state.page > 1) url.searchParams.set('page', String(state.page));
  else url.searchParams.delete('page');

  if (state.limit !== 20) url.searchParams.set('limit', String(state.limit));
  else url.searchParams.delete('limit');

  window.history.replaceState({}, '', url.toString());
}

async function loadHistoryData() {
  const skeleton = document.getElementById('history-loading-skeleton');
  const table = document.getElementById('history-table');
  const emptyState = document.getElementById('history-empty-state');
  const errorContainer = document.getElementById('history-error-container');

  if (skeleton) skeleton.classList.remove('d-none');
  if (table) table.classList.add('d-none');
  if (emptyState) emptyState.classList.add('d-none');

  try {
    const data = await getAnalyses({
      page: state.page,
      limit: state.limit,
      verdict: state.verdict,
      q: state.q
    });

    state.items = data.items || [];
    state.total = data.total ?? state.items.length;

    if (skeleton) skeleton.classList.add('d-none');

    sortItems();
    renderTable();
    renderPagination();
    updateResultsCount();
    updateUrlParams();

  } catch (err) {
    if (skeleton) skeleton.classList.add('d-none');
    if (errorContainer) {
      showErrorBanner(
        errorContainer,
        `Failed to retrieve analysis history: ${err.message || 'Server error'}`,
        loadHistoryData
      );
    }
  }
}

function sortItems() {
  state.items.sort((a, b) => {
    let aVal, bVal;
    switch (state.sortField) {
      case 'filename':
        aVal = (a.filename || '').toLowerCase();
        bVal = (b.filename || '').toLowerCase();
        break;
      case 'from':
        aVal = (a.envelope?.from || '').toLowerCase();
        bVal = (b.envelope?.from || '').toLowerCase();
        break;
      case 'subject':
        aVal = (a.envelope?.subject || '').toLowerCase();
        bVal = (b.envelope?.subject || '').toLowerCase();
        break;
      case 'score':
        aVal = a.risk?.score ?? 0;
        bVal = b.risk?.score ?? 0;
        break;
      case 'verdict':
        aVal = (a.risk?.verdict || '').toLowerCase();
        bVal = (b.risk?.verdict || '').toLowerCase();
        break;
      case 'date':
      default:
        aVal = new Date(a.analyzed_at || 0).getTime();
        bVal = new Date(b.analyzed_at || 0).getTime();
        break;
    }

    if (aVal < bVal) return state.sortAsc ? -1 : 1;
    if (aVal > bVal) return state.sortAsc ? 1 : -1;
    return 0;
  });
}

function renderTable() {
  const table = document.getElementById('history-table');
  const tbody = document.getElementById('history-tbody');
  const emptyState = document.getElementById('history-empty-state');

  if (!table || !tbody) return;

  if (state.items.length === 0) {
    table.classList.add('d-none');
    if (emptyState) {
      emptyState.classList.remove('d-none');
      showEmptyState(
        emptyState,
        state.q || state.verdict ? 'No analyses match your search criteria.' : 'No email forensic reports recorded yet.',
        'bi-search'
      );
    }
    return;
  }

  table.classList.remove('d-none');
  if (emptyState) emptyState.classList.add('d-none');
  tbody.innerHTML = '';

  state.items.forEach((item) => {
    const tr = document.createElement('tr');

    // Filename
    const tdFile = document.createElement('td');
    const nameLink = document.createElement('a');
    nameLink.href = `report.html?id=${encodeURIComponent(item.id)}`;
    nameLink.className = 'text-sand fw-medium text-decoration-none';
    nameLink.textContent = item.filename || 'unknown.eml';
    tdFile.appendChild(nameLink);

    // Sender
    const tdSender = document.createElement('td');
    tdSender.className = 'text-sand-muted mono text-sm';
    tdSender.textContent = truncate(item.envelope?.from || '—', 28);
    tdSender.title = item.envelope?.from || '';

    // Subject
    const tdSubject = document.createElement('td');
    tdSubject.className = 'text-sand text-sm';
    tdSubject.textContent = truncate(item.envelope?.subject || '—', 36);
    tdSubject.title = item.envelope?.subject || '';

    // Risk Score
    const tdScore = document.createElement('td');
    const scoreVal = item.risk?.score ?? 0;
    const scoreBadge = document.createElement('span');
    scoreBadge.className = 'badge';
    if (scoreVal >= 70) scoreBadge.className += ' badge-verdict--malicious';
    else if (scoreVal >= 30) scoreBadge.className += ' badge-verdict--suspicious';
    else scoreBadge.className += ' badge-verdict--clean';
    scoreBadge.textContent = `${scoreVal} / 100`;
    tdScore.appendChild(scoreBadge);

    // Verdict
    const tdVerdict = document.createElement('td');
    const verdict = (item.risk?.verdict || 'unknown').toLowerCase();
    const verdictSpan = document.createElement('span');
    verdictSpan.className = `badge-verdict badge-verdict--${verdict}`;
    verdictSpan.innerHTML = `<span class="badge-dot"></span><span>${verdict.toUpperCase()}</span>`;
    tdVerdict.appendChild(verdictSpan);

    // Date
    const tdDate = document.createElement('td');
    tdDate.className = 'text-sand-faint text-nowrap text-sm';
    tdDate.textContent = formatRelativeTime(item.analyzed_at);
    tdDate.title = formatDate(item.analyzed_at);

    // Actions (View + Delete)
    const tdActions = document.createElement('td');
    tdActions.className = 'text-end text-nowrap';

    const viewBtn = document.createElement('a');
    viewBtn.href = `report.html?id=${encodeURIComponent(item.id)}`;
    viewBtn.className = 'btn btn-sm btn-secondary me-1';
    viewBtn.innerHTML = '<i class="bi bi-eye me-1"></i> View';

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'btn btn-sm btn-ghost text-danger';
    delBtn.setAttribute('aria-label', `Delete ${item.filename}`);
    delBtn.innerHTML = '<i class="bi bi-trash3"></i>';
    delBtn.addEventListener('click', () => {
      showConfirmModal(
        'Delete Analysis Record',
        `Are you sure you want to delete forensic report "${item.filename}" (${item.id})?`,
        async () => {
          try {
            await deleteAnalysis(item.id);
            showToast('Analysis deleted', 'success');
            loadHistoryData();
          } catch (err) {
            showToast(`Deletion failed: ${err.message}`, 'error');
          }
        }
      );
    });

    tdActions.appendChild(viewBtn);
    tdActions.appendChild(delBtn);

    tr.appendChild(tdFile);
    tr.appendChild(tdSender);
    tr.appendChild(tdSubject);
    tr.appendChild(tdScore);
    tr.appendChild(tdVerdict);
    tr.appendChild(tdDate);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  });
}

function renderPagination() {
  const container = document.getElementById('pagination-controls');
  const infoEl = document.getElementById('pagination-info');
  if (!container) return;

  container.innerHTML = '';
  const totalPages = Math.ceil(state.total / state.limit) || 1;

  if (infoEl) {
    infoEl.textContent = `Page ${state.page} of ${totalPages}`;
  }

  if (totalPages <= 1) return;

  // Previous button
  const prevLi = document.createElement('li');
  prevLi.className = 'pagination-custom__item';
  const prevBtn = document.createElement('button');
  prevBtn.type = 'button';
  prevBtn.className = 'btn btn-sm btn-secondary';
  prevBtn.disabled = state.page <= 1;
  prevBtn.innerHTML = '<i class="bi bi-chevron-left"></i>';
  prevBtn.addEventListener('click', () => {
    if (state.page > 1) {
      state.page--;
      loadHistoryData();
    }
  });
  prevLi.appendChild(prevBtn);
  container.appendChild(prevLi);

  // Page Numbers
  for (let i = 1; i <= totalPages; i++) {
    const li = document.createElement('li');
    li.className = 'pagination-custom__item';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `btn btn-sm ${i === state.page ? 'btn-primary' : 'btn-secondary'}`;
    btn.textContent = String(i);
    btn.addEventListener('click', () => {
      if (state.page !== i) {
        state.page = i;
        loadHistoryData();
      }
    });
    li.appendChild(btn);
    container.appendChild(li);
  }

  // Next button
  const nextLi = document.createElement('li');
  nextLi.className = 'pagination-custom__item';
  const nextBtn = document.createElement('button');
  nextBtn.type = 'button';
  nextBtn.className = 'btn btn-sm btn-secondary';
  nextBtn.disabled = state.page >= totalPages;
  nextBtn.innerHTML = '<i class="bi bi-chevron-right"></i>';
  nextBtn.addEventListener('click', () => {
    if (state.page < totalPages) {
      state.page++;
      loadHistoryData();
    }
  });
  nextLi.appendChild(nextBtn);
  container.appendChild(nextLi);
}

function updateResultsCount() {
  const textEl = document.getElementById('results-count-text');
  if (!textEl) return;

  if (state.total === 0) {
    textEl.textContent = 'Showing 0 investigations';
    return;
  }

  const start = (state.page - 1) * state.limit + 1;
  const end = Math.min(state.page * state.limit, state.total);
  textEl.textContent = `Showing ${start}–${end} of ${state.total} investigations`;
}

function setupEventListeners() {
  // Search input (debounced)
  const searchInput = document.getElementById('history-search-input');
  if (searchInput) {
    searchInput.addEventListener(
      'input',
      debounce(() => {
        state.q = searchInput.value.trim();
        state.page = 1;
        loadHistoryData();
      }, 350)
    );
  }

  // Verdict filter select
  const verdictSelect = document.getElementById('history-verdict-filter');
  if (verdictSelect) {
    verdictSelect.addEventListener('change', () => {
      state.verdict = verdictSelect.value;
      state.page = 1;
      loadHistoryData();
    });
  }

  // Items per page select
  const limitSelect = document.getElementById('history-limit-select');
  if (limitSelect) {
    limitSelect.addEventListener('change', () => {
      state.limit = parseInt(limitSelect.value, 10) || 20;
      state.page = 1;
      loadHistoryData();
    });
  }

  // Reset filters
  const resetBtn = document.getElementById('reset-filters-btn');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      state.q = '';
      state.verdict = '';
      state.page = 1;
      if (searchInput) searchInput.value = '';
      if (verdictSelect) verdictSelect.value = '';
      loadHistoryData();
    });
  }

  // Sortable column headers
  const sortHeaders = document.querySelectorAll('[data-sort]');
  sortHeaders.forEach((th) => {
    th.addEventListener('click', () => {
      const field = th.getAttribute('data-sort');
      if (state.sortField === field) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortField = field;
        state.sortAsc = true;
      }
      sortItems();
      renderTable();
    });
  });
}
