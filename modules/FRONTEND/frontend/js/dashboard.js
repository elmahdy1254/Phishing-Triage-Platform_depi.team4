/**
 * Phishing Triage – Dashboard Controller
 * ========================================
 * Loads telemetry KPIs, initializes Chart.js visualizations,
 * and renders recent forensic triage investigations.
 */

import { getStats, getAnalyses } from './api.js';
import {
  formatDate,
  formatRelativeTime,
  truncate,
  getVerdictClass,
  getVerdictIcon
} from './utils.js';
import { showErrorBanner, showEmptyState } from './ui.js';
import { initLayout } from './layout.js';

let verdictChartInstance = null;
let trendChartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
  initLayout('dashboard');
  loadDashboardData();
});

async function loadDashboardData() {
  const errorContainer = document.getElementById('dashboard-error-container');

  try {
    // Parallel fetch of stats and recent analyses
    const [stats, analysesResult] = await Promise.all([
      getStats(),
      getAnalyses({ limit: 5 })
    ]);

    renderKPIs(stats);
    renderVerdictDonut(stats.verdict_distribution);
    renderTrendLine(stats.analyses_over_time);
    renderRecentAnalyses(analysesResult.items);
  } catch (err) {
    if (errorContainer) {
      showErrorBanner(
        errorContainer,
        `Unable to load dashboard telemetry: ${err.message || 'Server error'}`,
        loadDashboardData
      );
    }
  }
}

/**
 * Render the 4 KPI metric cards.
 */
function renderKPIs(stats) {
  const container = document.getElementById('kpi-container');
  if (!container || !stats) return;

  container.innerHTML = '';

  const kpis = [
    {
      label: 'Total Processed',
      value: stats.total_analyses != null ? stats.total_analyses.toLocaleString() : '0',
      icon: 'bi-envelope-check-fill',
      iconClass: 'kpi-card__icon--sand',
      badge: 'All sources',
      badgeClass: 'kpi-card__change--flat'
    },
    {
      label: 'Malicious Detections',
      value: stats.malicious_count != null ? stats.malicious_count.toLocaleString() : '0',
      icon: 'bi-shield-fill-x',
      iconClass: 'kpi-card__icon--danger',
      badge: 'High Risk',
      badgeClass: 'kpi-card__change--up'
    },
    {
      label: 'Average Risk Score',
      value: stats.avg_risk_score != null ? `${stats.avg_risk_score} / 100` : '—',
      icon: 'bi-speedometer2',
      iconClass: 'kpi-card__icon--warning',
      badge: stats.avg_risk_score > 60 ? 'Critical' : 'Moderate',
      badgeClass: stats.avg_risk_score > 60 ? 'kpi-card__change--up' : 'kpi-card__change--flat'
    },
    {
      label: 'Suspicious Queue',
      value: stats.suspicious_count != null ? stats.suspicious_count.toLocaleString() : '0',
      icon: 'bi-exclamation-octagon-fill',
      iconClass: 'kpi-card__icon--warning',
      badge: 'Needs Review',
      badgeClass: 'kpi-card__change--down'
    }
  ];

  kpis.forEach((kpi) => {
    const card = document.createElement('div');
    card.className = 'kpi-card';

    const header = document.createElement('div');
    header.className = 'kpi-card__header';

    const label = document.createElement('span');
    label.className = 'kpi-card__label';
    label.textContent = kpi.label;

    const iconDiv = document.createElement('div');
    iconDiv.className = `kpi-card__icon ${kpi.iconClass}`;
    const icon = document.createElement('i');
    icon.className = `bi ${kpi.icon}`;
    iconDiv.appendChild(icon);

    header.appendChild(label);
    header.appendChild(iconDiv);

    const valEl = document.createElement('div');
    valEl.className = 'kpi-card__value';
    valEl.textContent = kpi.value;

    const footer = document.createElement('div');
    footer.className = 'kpi-card__footer d-flex align-items-center justify-content-between';

    const change = document.createElement('span');
    change.className = `kpi-card__change ${kpi.badgeClass}`;
    change.textContent = kpi.badge;

    footer.appendChild(change);

    card.appendChild(header);
    card.appendChild(valEl);
    card.appendChild(footer);

    container.appendChild(card);
  });
}

/**
 * Chart.js Donut for verdict distribution.
 */
function renderVerdictDonut(dist) {
  const loading = document.getElementById('verdict-chart-loading');
  const wrapper = document.getElementById('verdict-chart-wrapper');
  const canvas = document.getElementById('verdictDistributionChart');

  if (loading) loading.classList.add('d-none');
  if (wrapper) wrapper.classList.remove('d-none');
  if (!canvas || !dist) return;

  if (verdictChartInstance) {
    verdictChartInstance.destroy();
  }

  /* global Chart */
  verdictChartInstance = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: dist.labels,
      datasets: [
        {
          data: dist.data,
          backgroundColor: ['#D9715F', '#D9A94F', '#8FB38A', '#8AA7B8'],
          borderColor: '#262624',
          borderWidth: 2,
          hoverOffset: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#D8CBB3',
            font: { family: 'Inter', size: 12 },
            padding: 16,
            usePointStyle: true,
            pointStyle: 'circle'
          }
        },
        tooltip: {
          backgroundColor: '#2E2E2B',
          titleColor: '#D8CBB3',
          bodyColor: '#D8CBB3',
          borderColor: 'rgba(216,203,179,0.2)',
          borderWidth: 1,
          padding: 10
        }
      },
      cutout: '72%'
    }
  });
}

/**
 * Chart.js Line chart for triage volume over time.
 */
function renderTrendLine(timeData) {
  const loading = document.getElementById('trend-chart-loading');
  const wrapper = document.getElementById('trend-chart-wrapper');
  const canvas = document.getElementById('analysesOverTimeChart');

  if (loading) loading.classList.add('d-none');
  if (wrapper) wrapper.classList.remove('d-none');
  if (!canvas || !timeData) return;

  if (trendChartInstance) {
    trendChartInstance.destroy();
  }

  const datasets = timeData.datasets.map((ds) => ({
    label: ds.label,
    data: ds.data,
    borderColor: ds.color,
    backgroundColor: `${ds.color}22`,
    fill: true,
    tension: 0.35,
    borderWidth: 2,
    pointRadius: 3,
    pointHoverRadius: 5
  }));

  trendChartInstance = new Chart(canvas, {
    type: 'line',
    data: {
      labels: timeData.labels.map((d) => d.replace(/^\d{4}-/, '')),
      datasets
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false
      },
      scales: {
        x: {
          grid: { color: 'rgba(216,203,179,0.06)' },
          ticks: { color: 'rgba(216,203,179,0.6)', font: { family: 'Inter', size: 11 } }
        },
        y: {
          grid: { color: 'rgba(216,203,179,0.06)' },
          ticks: { color: 'rgba(216,203,179,0.6)', font: { family: 'Inter', size: 11 } },
          beginAtZero: true
        }
      },
      plugins: {
        legend: {
          position: 'top',
          align: 'end',
          labels: {
            color: '#D8CBB3',
            font: { family: 'Inter', size: 11 },
            usePointStyle: true,
            boxWidth: 8
          }
        },
        tooltip: {
          backgroundColor: '#2E2E2B',
          titleColor: '#D8CBB3',
          bodyColor: '#D8CBB3',
          borderColor: 'rgba(216,203,179,0.2)',
          borderWidth: 1,
          padding: 10
        }
      }
    }
  });
}

/**
 * Safely render recent analyses rows.
 */
function renderRecentAnalyses(analyses) {
  const loading = document.getElementById('recent-analyses-loading');
  const table = document.getElementById('recent-analyses-table');
  const tbody = document.getElementById('recent-analyses-tbody');
  const container = document.getElementById('recent-analyses-container');

  if (loading) loading.classList.add('d-none');

  if (!analyses || analyses.length === 0) {
    if (table) table.classList.add('d-none');
    if (container) {
      showEmptyState(container, 'No email forensic reports recorded yet.', 'bi-inbox');
    }
    return;
  }

  if (table) table.classList.remove('d-none');
  if (tbody) tbody.innerHTML = '';

  analyses.forEach((item) => {
    const tr = document.createElement('tr');

    // 1. Filename
    const tdFile = document.createElement('td');
    const fileSpan = document.createElement('span');
    fileSpan.className = 'fw-medium text-sand';
    fileSpan.textContent = item.filename || 'unknown.eml';
    tdFile.appendChild(fileSpan);

    // 2. Sender
    const tdSender = document.createElement('td');
    tdSender.className = 'text-sand-muted mono';
    tdSender.textContent = truncate(item.envelope?.from || '—', 28);
    tdSender.title = item.envelope?.from || '';

    // 3. Subject
    const tdSubject = document.createElement('td');
    tdSubject.className = 'text-sand';
    tdSubject.textContent = truncate(item.envelope?.subject || '—', 36);
    tdSubject.title = item.envelope?.subject || '';

    // 4. Risk Score
    const tdScore = document.createElement('td');
    const scoreVal = item.risk?.score ?? 0;
    const scoreBadge = document.createElement('span');
    scoreBadge.className = 'badge';
    if (scoreVal >= 70) {
      scoreBadge.className += ' badge-verdict--malicious';
    } else if (scoreVal >= 30) {
      scoreBadge.className += ' badge-verdict--suspicious';
    } else {
      scoreBadge.className += ' badge-verdict--clean';
    }
    scoreBadge.textContent = `${scoreVal} / 100`;
    tdScore.appendChild(scoreBadge);

    // 5. Verdict
    const tdVerdict = document.createElement('td');
    const verdict = item.risk?.verdict || 'unknown';
    const verdictSpan = document.createElement('span');
    verdictSpan.className = `badge-verdict badge-verdict--${verdict}`;

    const dot = document.createElement('span');
    dot.className = 'badge-dot';
    const vText = document.createElement('span');
    vText.textContent = verdict.toUpperCase();

    verdictSpan.appendChild(dot);
    verdictSpan.appendChild(vText);
    tdVerdict.appendChild(verdictSpan);

    // 6. Analyzed date
    const tdDate = document.createElement('td');
    tdDate.className = 'text-sand-faint text-nowrap';
    tdDate.textContent = formatRelativeTime(item.analyzed_at);
    tdDate.title = formatDate(item.analyzed_at);

    // 7. Actions
    const tdAction = document.createElement('td');
    tdAction.className = 'text-end';
    const viewBtn = document.createElement('a');
    viewBtn.href = `report.html?id=${encodeURIComponent(item.id)}`;
    viewBtn.className = 'btn btn-sm btn-secondary';
    viewBtn.innerHTML = 'View <i class="bi bi-arrow-right ms-1" aria-hidden="true"></i>';
    tdAction.appendChild(viewBtn);

    tr.appendChild(tdFile);
    tr.appendChild(tdSender);
    tr.appendChild(tdSubject);
    tr.appendChild(tdScore);
    tr.appendChild(tdVerdict);
    tr.appendChild(tdDate);
    tr.appendChild(tdAction);

    tbody.appendChild(tr);
  });
}
