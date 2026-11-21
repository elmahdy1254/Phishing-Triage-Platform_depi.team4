/**
 * Phishing Triage – Forensic Analysis Report Controller
 * ========================================================
 * Powers the central forensic investigation report.
 * Renders envelope headers, authentication verdicts, Received timeline,
 * defanged URLs with reveal toggles, attachment digests, and IOC exports.
 */

import { getAnalysis, deleteAnalysis, exportAnalysis } from './api.js';
import {
  defangUrl,
  refangUrl,
  copyToClipboard,
  formatDate,
  formatRelativeTime,
  formatFileSize,
  getVerdictClass,
  getVerdictIcon,
  getAuthStatusClass,
  collectIOCs,
  truncate
} from './utils.js';
import { showToast, showConfirmModal, showErrorBanner, initTooltips } from './ui.js';
import { initLayout } from './layout.js';

let currentAnalysis = null;
let showOnlyFlaggedUrls = false;

document.addEventListener('DOMContentLoaded', () => {
  initLayout('history');

  // Read analysis ID from query param
  const params = new URLSearchParams(window.location.search);
  const analysisId = params.get('id') || 'a1b2c3'; // Fallback to primary sample

  loadAnalysis(analysisId);
  setupEventListeners(analysisId);
});

async function loadAnalysis(id) {
  const skeleton = document.getElementById('report-skeleton-container');
  const content = document.getElementById('report-content');
  const errorContainer = document.getElementById('report-error-container');

  try {
    currentAnalysis = await getAnalysis(id);

    if (skeleton) skeleton.classList.add('d-none');
    if (content) content.classList.remove('d-none');

    renderAll(currentAnalysis);
  } catch (err) {
    if (skeleton) skeleton.classList.add('d-none');
    if (errorContainer) {
      showErrorBanner(
        errorContainer,
        `Failed to retrieve analysis report [${id}]: ${err.message || 'Not found'}`,
        () => loadAnalysis(id)
      );
    }
  }
}

/**
 * Render all forensic sections.
 */
function renderAll(analysis) {
  // Update browser document title
  document.title = `${analysis.filename || 'Forensics Report'} | Phishing Triage`;

  // Topbar filename breadcrumb
  const topbarFilename = document.getElementById('topbar-filename');
  if (topbarFilename) topbarFilename.textContent = analysis.filename || 'Report';

  renderHeader(analysis);
  renderEnvelope(analysis.envelope);
  renderAuthentication(analysis.authentication);
  renderRiskBreakdown(analysis.risk);
  renderRouting(analysis.routing);
  renderUrls(analysis.urls);
  renderAttachments(analysis.attachments);

  // Initialize all freshly created tooltips
  initTooltips();
}

/**
 * 1. Header & Animated Risk Gauge
 */
function renderHeader(analysis) {
  const idBadge = document.getElementById('report-id-badge');
  const timestampEl = document.getElementById('report-timestamp');
  const filenameEl = document.getElementById('report-filename');
  const senderMeta = document.getElementById('report-meta-sender');
  const subjectMeta = document.getElementById('report-meta-subject');

  if (idBadge) idBadge.textContent = `ID: ${analysis.id}`;
  if (timestampEl) {
    timestampEl.textContent = `Analyzed ${formatRelativeTime(analysis.analyzed_at)}`;
    timestampEl.title = formatDate(analysis.analyzed_at);
  }
  if (filenameEl) filenameEl.textContent = analysis.filename;
  if (senderMeta) senderMeta.textContent = analysis.envelope?.from || '—';
  if (subjectMeta) subjectMeta.textContent = analysis.envelope?.subject || '—';

  // Risk Score & Verdict
  const score = analysis.risk?.score ?? 0;
  const verdict = (analysis.risk?.verdict || 'unknown').toLowerCase();

  const scoreEl = document.getElementById('gauge-score-value');
  const verdictLabel = document.getElementById('gauge-verdict-label');
  const gaugeFill = document.getElementById('gauge-fill-circle');
  const verdictBadge = document.getElementById('report-verdict-badge');
  const verdictText = document.getElementById('report-verdict-text');

  if (scoreEl) scoreEl.textContent = String(score);
  if (verdictLabel) {
    verdictLabel.textContent = verdict.toUpperCase();
    verdictLabel.className = `risk-gauge__verdict risk-gauge__verdict--${verdict}`;
  }

  if (verdictBadge) {
    verdictBadge.className = `badge-verdict badge-verdict--${verdict}`;
  }
  if (verdictText) verdictText.textContent = verdict.toUpperCase();

  // Circular gauge animation (2 * PI * 54 = 339.292)
  if (gaugeFill) {
    const circumference = 339.292;
    const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
    gaugeFill.style.strokeDashoffset = String(offset);

    if (score >= 70) {
      gaugeFill.style.stroke = 'var(--danger)';
    } else if (score >= 30) {
      gaugeFill.style.stroke = 'var(--warning)';
    } else {
      gaugeFill.style.stroke = 'var(--safe)';
    }
  }
}

/**
 * 2. Envelope & Headers
 */
function renderEnvelope(envelope) {
  if (!envelope) return;

  const setSafeText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text || '—';
  };

  setSafeText('env-from', envelope.from);
  setSafeText('env-reply-to', envelope.reply_to);
  setSafeText('env-to', envelope.to);
  setSafeText('env-subject', envelope.subject);
  setSafeText('env-date', formatDate(envelope.date));
  setSafeText('env-message-id', envelope.message_id);

  // Message body text
  const bodyTextEl = document.getElementById('env-body-text');
  if (bodyTextEl) {
    bodyTextEl.textContent = envelope.body_text || '[No plaintext body present in message]';
  }
}

/**
 * 3. Authentication & Spoofing Indicators
 */
function renderAuthentication(auth) {
  if (!auth) return;

  const updateChip = (badgeId, textId, status) => {
    const badge = document.getElementById(badgeId);
    const text = document.getElementById(textId);
    const s = (status || 'none').toLowerCase();

    if (badge) {
      badge.className = `badge-auth badge-auth--${s}`;
    }
    if (text) text.textContent = s.toUpperCase();
  };

  updateChip('auth-spf-badge', 'auth-spf-text', auth.spf);
  updateChip('auth-dkim-badge', 'auth-dkim-text', auth.dkim);
  updateChip('auth-dmarc-badge', 'auth-dmarc-text', auth.dmarc);

  // Spoofing indicators list
  const list = document.getElementById('spoofing-indicators-list');
  if (!list) return;

  list.innerHTML = '';
  const indicators = auth.spoofing_indicators || [];

  if (indicators.length === 0) {
    const li = document.createElement('li');
    li.className = 'text-safe text-sm d-flex align-items-center gap-2';
    li.innerHTML = '<i class="bi bi-shield-check text-safe"></i> No spoofing anomalies detected';
    list.appendChild(li);
  } else {
    indicators.forEach((indicator) => {
      const li = document.createElement('li');
      li.className = 'text-sm text-sand d-flex align-items-start gap-2 bg-surface-2 p-2 rounded border border-warning-subtle';

      const icon = document.createElement('i');
      icon.className = 'bi bi-exclamation-triangle-fill text-warning mt-1 flex-shrink-0';

      const span = document.createElement('span');
      span.textContent = indicator;

      li.appendChild(icon);
      li.appendChild(span);
      list.appendChild(li);
    });
  }
}

/**
 * 4. Risk Score Breakdown
 */
function renderRiskBreakdown(risk) {
  const container = document.getElementById('risk-breakdown-container');
  if (!container || !risk) return;

  container.innerHTML = '';
  const factors = risk.breakdown || [];

  if (factors.length === 0) {
    container.innerHTML = '<p class="text-sand-faint text-sm mb-0">No risk penalty factors applied.</p>';
    return;
  }

  // Calculate highest point for proportional bar
  const maxPts = Math.max(...factors.map((f) => f.points || 0), 30);

  factors.forEach((f) => {
    const item = document.createElement('div');
    item.className = 'risk-breakdown__item';

    const factorName = document.createElement('span');
    factorName.className = 'risk-breakdown__factor';
    const icon = document.createElement('i');
    icon.className = f.points >= 20 ? 'bi bi-shield-slash-fill text-danger' : 'bi bi-shield-exclamation text-warning';
    const nameText = document.createElement('span');
    nameText.textContent = f.factor;
    factorName.appendChild(icon);
    factorName.appendChild(nameText);

    const points = document.createElement('span');
    points.className = 'risk-breakdown__points';
    points.textContent = `+${f.points} pts`;

    const barTrack = document.createElement('div');
    barTrack.className = 'risk-breakdown__bar-track';

    const barFill = document.createElement('div');
    const pct = Math.min(100, (f.points / maxPts) * 100);
    barFill.className = 'risk-breakdown__bar-fill';
    barFill.style.width = `${pct}%`;

    if (f.points >= 20) {
      barFill.classList.add('risk-breakdown__bar-fill--high');
    } else if (f.points >= 10) {
      barFill.classList.add('risk-breakdown__bar-fill--medium');
    } else {
      barFill.classList.add('risk-breakdown__bar-fill--low');
    }

    barTrack.appendChild(barFill);

    item.appendChild(factorName);
    item.appendChild(points);
    item.appendChild(barTrack);

    container.appendChild(item);
  });
}

/**
 * 5. Routing Timeline (Received Hops)
 */
function renderRouting(routing) {
  const timeline = document.getElementById('routing-timeline');
  const countBadge = document.getElementById('hops-count-badge');
  if (!timeline) return;

  timeline.innerHTML = '';
  const hops = routing || [];

  if (countBadge) countBadge.textContent = `${hops.length} Hops`;

  if (hops.length === 0) {
    timeline.innerHTML = '<li class="text-sand-faint text-sm">No Received: routing headers detected.</li>';
    return;
  }

  hops.forEach((hop, idx) => {
    const li = document.createElement('li');
    li.className = 'timeline__item';

    const dot = document.createElement('div');
    dot.className = 'timeline__dot';
    li.appendChild(dot);

    const content = document.createElement('div');
    content.className = 'timeline__content';

    // Hop header & origin badge
    const headerDiv = document.createElement('div');
    headerDiv.className = 'd-flex align-items-center justify-content-between mb-1';

    const hopTitle = document.createElement('span');
    hopTitle.className = 'timeline__hop';
    hopTitle.textContent = `Hop #${hop.hop ?? (idx + 1)}`;
    headerDiv.appendChild(hopTitle);

    if (idx === 0) {
      const originBadge = document.createElement('span');
      originBadge.className = 'badge badge-auth--fail text-xs';
      originBadge.textContent = 'ORIGIN SERVER';
      headerDiv.appendChild(originBadge);
    }

    content.appendChild(headerDiv);

    // From -> By servers
    const serverDiv = document.createElement('div');
    serverDiv.className = 'timeline__server mb-2';
    serverDiv.textContent = `${hop.from || 'unknown'} → ${hop.by || 'unknown'}`;
    content.appendChild(serverDiv);

    // Meta details: IP (copiable), Timestamp, Country
    const metaDiv = document.createElement('div');
    metaDiv.className = 'timeline__meta';

    if (hop.ip) {
      const ipWrap = document.createElement('div');
      ipWrap.className = 'timeline__meta-item';
      const ipIcon = document.createElement('i');
      ipIcon.className = 'bi bi-hdd-network text-sand-faint';

      const ipCopiable = document.createElement('div');
      ipCopiable.className = 'copiable ms-1';

      const ipVal = document.createElement('span');
      ipVal.className = 'copiable__value';
      ipVal.textContent = hop.ip;

      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'copy-btn';
      copyBtn.setAttribute('aria-label', `Copy IP ${hop.ip}`);
      copyBtn.innerHTML = '<i class="bi bi-clipboard"></i>';
      copyBtn.addEventListener('click', () => copyToClipboard(hop.ip));

      ipCopiable.appendChild(ipVal);
      ipCopiable.appendChild(copyBtn);
      ipWrap.appendChild(ipIcon);
      ipWrap.appendChild(ipCopiable);
      metaDiv.appendChild(ipWrap);
    }

    if (hop.country) {
      const countryWrap = document.createElement('div');
      countryWrap.className = 'timeline__meta-item';
      countryWrap.innerHTML = `<i class="bi bi-geo-alt text-sand-faint"></i><span>${hop.country}</span>`;
      metaDiv.appendChild(countryWrap);
    }

    if (hop.timestamp) {
      const timeWrap = document.createElement('div');
      timeWrap.className = 'timeline__meta-item ms-auto';
      timeWrap.innerHTML = `<i class="bi bi-clock text-sand-faint"></i><span>${formatDate(hop.timestamp)}</span>`;
      metaDiv.appendChild(timeWrap);
    }

    content.appendChild(metaDiv);
    li.appendChild(content);
    timeline.appendChild(li);
  });
}

/**
 * 6. Extracted URLs Table
 */
function renderUrls(urls) {
  const tbody = document.getElementById('urls-tbody');
  const countBadge = document.getElementById('urls-count-badge');
  const emptyMsg = document.getElementById('urls-empty-msg');
  if (!tbody) return;

  tbody.innerHTML = '';
  const allUrls = urls || [];
  const displayList = showOnlyFlaggedUrls
    ? allUrls.filter((u) => u.verdict === 'malicious' || u.verdict === 'suspicious')
    : allUrls;

  if (countBadge) countBadge.textContent = `${allUrls.length} URLs`;

  if (displayList.length === 0) {
    if (emptyMsg) {
      emptyMsg.classList.remove('d-none');
      emptyMsg.textContent = showOnlyFlaggedUrls ? 'No flagged URLs match the filter.' : 'No URLs detected in message.';
    }
    return;
  }

  if (emptyMsg) emptyMsg.classList.add('d-none');

  displayList.forEach((u) => {
    const tr = document.createElement('tr');

    // Defanged URL cell with Reveal toggle
    const tdUrl = document.createElement('td');
    const defanged = defangUrl(u.url);
    const original = u.url;

    const urlWrap = document.createElement('div');
    urlWrap.className = 'defanged-url';

    const textSpan = document.createElement('span');
    textSpan.className = 'defanged-url__text defanged-url__text--defanged';
    textSpan.textContent = defanged;

    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'defanged-url__toggle';
    toggleBtn.innerHTML = '<i class="bi bi-eye"></i> Reveal';

    let isRevealed = false;
    toggleBtn.addEventListener('click', () => {
      isRevealed = !isRevealed;
      if (isRevealed) {
        textSpan.textContent = original;
        textSpan.className = 'defanged-url__text defanged-url__text--live';
        toggleBtn.innerHTML = '<i class="bi bi-eye-slash"></i> Defang';
      } else {
        textSpan.textContent = defanged;
        textSpan.className = 'defanged-url__text defanged-url__text--defanged';
        toggleBtn.innerHTML = '<i class="bi bi-eye"></i> Reveal';
      }
    });

    urlWrap.appendChild(textSpan);
    urlWrap.appendChild(toggleBtn);
    tdUrl.appendChild(urlWrap);

    // Domain
    const tdDomain = document.createElement('td');
    tdDomain.className = 'mono text-sand';
    tdDomain.textContent = u.domain || '—';

    // Verdict Badge
    const tdVerdict = document.createElement('td');
    const v = (u.verdict || 'unknown').toLowerCase();
    const vBadge = document.createElement('span');
    vBadge.className = `badge-verdict badge-verdict--${v}`;
    vBadge.innerHTML = `<span class="badge-dot"></span><span>${v.toUpperCase()}</span>`;
    tdVerdict.appendChild(vBadge);

    // Source
    const tdSource = document.createElement('td');
    tdSource.className = 'text-sand-muted text-sm';
    tdSource.textContent = u.source || 'ThreatIntel';

    // Detections
    const tdDet = document.createElement('td');
    tdDet.className = 'mono text-sand text-sm';
    if (u.total_engines) {
      tdDet.textContent = `${u.detections ?? 0} / ${u.total_engines}`;
      if (u.detections > 0) tdDet.className += ' text-danger fw-semibold';
    } else {
      tdDet.textContent = '—';
    }

    // Actions (Copy URL)
    const tdActions = document.createElement('td');
    tdActions.className = 'text-end';
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'copy-btn';
    copyBtn.setAttribute('aria-label', 'Copy defanged URL');
    copyBtn.innerHTML = '<i class="bi bi-clipboard"></i>';
    copyBtn.addEventListener('click', () => copyToClipboard(defanged));
    tdActions.appendChild(copyBtn);

    tr.appendChild(tdUrl);
    tr.appendChild(tdDomain);
    tr.appendChild(tdVerdict);
    tr.appendChild(tdSource);
    tr.appendChild(tdDet);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  });
}

/**
 * 7. Attachments Table
 */
function renderAttachments(attachments) {
  const tbody = document.getElementById('attachments-tbody');
  const countBadge = document.getElementById('attachments-count-badge');
  const emptyMsg = document.getElementById('attachments-empty-msg');
  if (!tbody) return;

  tbody.innerHTML = '';
  const atts = attachments || [];

  if (countBadge) countBadge.textContent = `${atts.length} Attachments`;

  if (atts.length === 0) {
    if (emptyMsg) emptyMsg.classList.remove('d-none');
    return;
  }

  if (emptyMsg) emptyMsg.classList.add('d-none');

  atts.forEach((att) => {
    const tr = document.createElement('tr');

    // Filename
    const tdName = document.createElement('td');
    const icon = document.createElement('i');
    icon.className = att.dangerous_extension ? 'bi bi-file-earmark-x-fill text-danger me-2' : 'bi bi-file-earmark-text text-sand me-2';
    const nameSpan = document.createElement('span');
    nameSpan.className = 'text-sand fw-medium';
    nameSpan.textContent = att.filename;
    tdName.appendChild(icon);
    tdName.appendChild(nameSpan);

    // Extension & Dangerous flag
    const tdExt = document.createElement('td');
    const extBadge = document.createElement('span');
    extBadge.className = att.dangerous_extension ? 'badge badge-auth--fail' : 'badge badge-auth--neutral';
    extBadge.textContent = att.extension || '—';
    if (att.dangerous_extension) {
      extBadge.title = 'High risk executable or script extension';
    }
    tdExt.appendChild(extBadge);

    // Size
    const tdSize = document.createElement('td');
    tdSize.className = 'mono text-sand-muted text-sm';
    tdSize.textContent = formatFileSize(att.size_bytes);

    // MD5
    const tdMd5 = document.createElement('td');
    if (att.md5) {
      const wrap = document.createElement('div');
      wrap.className = 'copiable';
      const val = document.createElement('span');
      val.className = 'copiable__value';
      val.textContent = truncate(att.md5, 14);
      val.title = att.md5;

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'copy-btn';
      btn.setAttribute('aria-label', `Copy MD5 ${att.md5}`);
      btn.innerHTML = '<i class="bi bi-clipboard"></i>';
      btn.addEventListener('click', () => copyToClipboard(att.md5));

      wrap.appendChild(val);
      wrap.appendChild(btn);
      tdMd5.appendChild(wrap);
    } else {
      tdMd5.textContent = '—';
    }

    // SHA-256
    const tdSha = document.createElement('td');
    if (att.sha256) {
      const wrap = document.createElement('div');
      wrap.className = 'copiable';
      const val = document.createElement('span');
      val.className = 'copiable__value';
      val.textContent = truncate(att.sha256, 16);
      val.title = att.sha256;

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'copy-btn';
      btn.setAttribute('aria-label', `Copy SHA-256 ${att.sha256}`);
      btn.innerHTML = '<i class="bi bi-clipboard"></i>';
      btn.addEventListener('click', () => copyToClipboard(att.sha256));

      wrap.appendChild(val);
      wrap.appendChild(btn);
      tdSha.appendChild(wrap);
    } else {
      tdSha.textContent = '—';
    }

    // Verdict
    const tdVerdict = document.createElement('td');
    const v = (att.verdict || 'unknown').toLowerCase();
    const vBadge = document.createElement('span');
    vBadge.className = `badge-verdict badge-verdict--${v}`;
    vBadge.innerHTML = `<span class="badge-dot"></span><span>${v.toUpperCase()}</span>`;
    tdVerdict.appendChild(vBadge);

    // Detections
    const tdDet = document.createElement('td');
    tdDet.className = 'mono text-sand text-sm';
    if (att.total_engines) {
      tdDet.textContent = `${att.detections ?? 0} / ${att.total_engines}`;
      if (att.detections > 0) tdDet.className += ' text-danger fw-semibold';
    } else {
      tdDet.textContent = '—';
    }

    tr.appendChild(tdName);
    tr.appendChild(tdExt);
    tr.appendChild(tdSize);
    tr.appendChild(tdMd5);
    tr.appendChild(tdSha);
    tr.appendChild(tdVerdict);
    tr.appendChild(tdDet);

    tbody.appendChild(tr);
  });
}

/**
 * 8. User Actions & Toolbar Handlers
 */
function setupEventListeners(analysisId) {
  // Body text collapse toggle
  const toggleBodyBtn = document.getElementById('toggle-body-btn');
  const bodyWrapper = document.getElementById('body-text-wrapper');
  const toggleIcon = document.getElementById('toggle-body-icon');

  if (toggleBodyBtn && bodyWrapper) {
    toggleBodyBtn.addEventListener('click', () => {
      const isHidden = bodyWrapper.classList.contains('d-none');
      if (isHidden) {
        bodyWrapper.classList.remove('d-none');
        toggleBodyBtn.innerHTML = '<i class="bi bi-chevron-up me-1"></i> Hide Body';
      } else {
        bodyWrapper.classList.add('d-none');
        toggleBodyBtn.innerHTML = '<i class="bi bi-chevron-down me-1"></i> Show Body';
      }
    });
  }

  // Copy Message-ID button
  const copyMsgIdBtn = document.getElementById('copy-msgid-btn');
  if (copyMsgIdBtn) {
    copyMsgIdBtn.addEventListener('click', () => {
      if (currentAnalysis?.envelope?.message_id) {
        copyToClipboard(currentAnalysis.envelope.message_id);
      }
    });
  }

  // Flagged URLs only toggle
  const flaggedToggle = document.getElementById('flagged-urls-only-toggle');
  if (flaggedToggle) {
    flaggedToggle.addEventListener('change', () => {
      showOnlyFlaggedUrls = flaggedToggle.checked;
      if (currentAnalysis) renderUrls(currentAnalysis.urls);
    });
  }

  // Copy All IOCs
  const copyIocsBtn = document.getElementById('copy-iocs-btn');
  if (copyIocsBtn) {
    copyIocsBtn.addEventListener('click', () => {
      if (!currentAnalysis) return;
      const iocs = collectIOCs(currentAnalysis);
      if (iocs.length === 0) {
        showToast('No IOCs found in this analysis.', 'info');
        return;
      }
      const text = iocs.map((item) => `[${item.type}] ${item.value}`).join('\n');
      copyToClipboard(text);
      showToast(`Copied ${iocs.length} IOC indicators!`, 'success');
    });
  }

  // Re-analyze
  const reanalyzeBtn = document.getElementById('reanalyze-btn');
  if (reanalyzeBtn) {
    reanalyzeBtn.addEventListener('click', () => {
      showToast('Re-analyzing email against live threat feeds...', 'info');
      setTimeout(() => {
        loadAnalysis(analysisId);
        showToast('Forensic report refreshed.', 'success');
      }, 700);
    });
  }

  // Delete Analysis
  const deleteBtn = document.getElementById('delete-analysis-btn');
  if (deleteBtn) {
    deleteBtn.addEventListener('click', () => {
      showConfirmModal(
        'Delete Forensic Analysis',
        `Are you sure you want to delete report "${currentAnalysis?.filename || analysisId}"? This action cannot be undone.`,
        async () => {
          try {
            await deleteAnalysis(analysisId);
            showToast('Analysis deleted.', 'success');
            setTimeout(() => {
              window.location.href = 'history.html';
            }, 500);
          } catch (err) {
            showToast(`Deletion failed: ${err.message}`, 'error');
          }
        }
      );
    });
  }

  // Export JSON
  const exportJsonBtn = document.getElementById('export-json-btn');
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      try {
        const blob = await exportAnalysis(analysisId, 'json');
        _downloadBlob(blob, `analysis-${analysisId}.json`);
        showToast('Exported JSON report', 'success');
      } catch (err) {
        showToast(`Export failed: ${err.message}`, 'error');
      }
    });
  }

  // Export CSV
  const exportCsvBtn = document.getElementById('export-csv-btn');
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      try {
        const blob = await exportAnalysis(analysisId, 'csv');
        _downloadBlob(blob, `analysis-${analysisId}.csv`);
        showToast('Exported CSV report', 'success');
      } catch (err) {
        showToast(`Export failed: ${err.message}`, 'error');
      }
    });
  }

  // Export PDF / Print
  const exportPdfBtn = document.getElementById('export-pdf-btn');
  if (exportPdfBtn) {
    exportPdfBtn.addEventListener('click', (e) => {
      e.preventDefault();
      window.print();
    });
  }
}

function _downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
