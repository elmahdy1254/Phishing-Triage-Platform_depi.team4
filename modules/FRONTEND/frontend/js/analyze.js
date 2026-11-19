/**
 * Phishing Triage – New Analysis Controller
 * ==========================================
 * Manages email file drag-and-drop, client-side MIME/size validation,
 * upload staging, progress animation, and routing to forensic reports.
 */

import { analyze } from './api.js';
import { MAX_FILE_SIZE, ALLOWED_EXTENSIONS } from './config.js';
import { formatFileSize } from './utils.js';
import { showToast, showErrorBanner, hideErrorBanner } from './ui.js';
import { initLayout } from './layout.js';

let stagedFiles = [];
let isUploading = false;

document.addEventListener('DOMContentLoaded', () => {
  initLayout('analyze');
  setupUploadZone();
});

function setupUploadZone() {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const startBtn = document.getElementById('start-analysis-btn');
  const clearBtn = document.getElementById('clear-all-btn');

  if (!dropZone || !fileInput) return;

  // Drag over animations
  ['dragenter', 'dragover'].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (!isUploading) {
        dropZone.classList.add('drag-over');
      }
    });
  });

  ['dragleave', 'drop'].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('drag-over');
    });
  });

  // Handle dropped files
  dropZone.addEventListener('drop', (e) => {
    if (isUploading) return;
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      handleFilesSelected(Array.from(files));
    }
  });

  // Handle file input selection
  fileInput.addEventListener('change', () => {
    if (isUploading) return;
    if (fileInput.files && fileInput.files.length > 0) {
      handleFilesSelected(Array.from(fileInput.files));
      fileInput.value = ''; // Reset for re-selection
    }
  });

  // Clear staged files
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (isUploading) return;
      stagedFiles = [];
      renderStagedFiles();
    });
  }

  // Start analysis
  if (startBtn) {
    startBtn.addEventListener('click', () => {
      if (stagedFiles.length === 0 || isUploading) return;
      startUploadProcess();
    });
  }
}

/**
 * Validate and add files to the staged queue.
 */
function handleFilesSelected(newFiles) {
  const errorContainer = document.getElementById('upload-error-container');
  if (errorContainer) hideErrorBanner(errorContainer);

  const errors = [];

  newFiles.forEach((file) => {
    // 1. Check extension
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      errors.push(`"${file.name}": Unsupported format. Only .eml and .msg files are allowed.`);
      return;
    }

    // 2. Check file size
    if (file.size > MAX_FILE_SIZE) {
      const maxMb = (MAX_FILE_SIZE / (1024 * 1024)).toFixed(0);
      errors.push(`"${file.name}": Exceeds maximum size of ${maxMb} MB (${formatFileSize(file.size)}).`);
      return;
    }

    // 3. Avoid duplicates in current queue
    const alreadyStaged = stagedFiles.some((f) => f.name === file.name && f.size === file.size);
    if (!alreadyStaged) {
      stagedFiles.push(file);
    }
  });

  if (errors.length > 0 && errorContainer) {
    showErrorBanner(errorContainer, errors.join(' '));
  }

  renderStagedFiles();
}

/**
 * Render the staged files list table.
 */
function renderStagedFiles() {
  const section = document.getElementById('selected-files-section');
  const tbody = document.getElementById('staged-files-tbody');
  const countEl = document.getElementById('staged-count');
  const startBtn = document.getElementById('start-analysis-btn');

  if (!section || !tbody) return;

  if (countEl) countEl.textContent = String(stagedFiles.length);

  if (stagedFiles.length === 0) {
    section.classList.add('d-none');
    if (startBtn) startBtn.disabled = true;
    return;
  }

  section.classList.remove('d-none');
  if (startBtn) startBtn.disabled = isUploading;

  tbody.innerHTML = '';

  stagedFiles.forEach((file, index) => {
    const tr = document.createElement('tr');

    // Filename
    const tdName = document.createElement('td');
    const icon = document.createElement('i');
    icon.className = 'bi bi-file-earmark-text text-sand me-2';
    const nameSpan = document.createElement('span');
    nameSpan.className = 'text-sand fw-medium';
    nameSpan.textContent = file.name;
    tdName.appendChild(icon);
    tdName.appendChild(nameSpan);

    // Size
    const tdSize = document.createElement('td');
    tdSize.className = 'mono text-sand-muted';
    tdSize.textContent = formatFileSize(file.size);

    // Status
    const tdStatus = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge badge-auth--neutral';
    badge.textContent = 'Ready';
    tdStatus.appendChild(badge);

    // Action
    const tdAction = document.createElement('td');
    tdAction.className = 'text-end';
    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'btn btn-sm btn-ghost text-danger';
    removeBtn.setAttribute('aria-label', `Remove ${file.name}`);
    removeBtn.innerHTML = '<i class="bi bi-x-circle" aria-hidden="true"></i>';

    removeBtn.addEventListener('click', () => {
      if (isUploading) return;
      stagedFiles.splice(index, 1);
      renderStagedFiles();
    });

    tdAction.appendChild(removeBtn);

    tr.appendChild(tdName);
    tr.appendChild(tdSize);
    tr.appendChild(tdStatus);
    tr.appendChild(tdAction);

    tbody.appendChild(tr);
  });
}

/**
 * Execute upload and parsing for all staged files.
 */
async function startUploadProcess() {
  const errorContainer = document.getElementById('upload-error-container');
  const progressWrapper = document.getElementById('upload-progress-wrapper');
  const progressBar = document.getElementById('upload-progress-bar');
  const progressPercent = document.getElementById('upload-progress-percent');
  const progressLabel = document.getElementById('upload-progress-label');
  const startBtn = document.getElementById('start-analysis-btn');
  const dropZone = document.getElementById('drop-zone');

  if (errorContainer) hideErrorBanner(errorContainer);

  isUploading = true;
  if (startBtn) startBtn.disabled = true;
  if (dropZone) dropZone.classList.add('uploading');
  if (progressWrapper) progressWrapper.classList.remove('d-none');

  let completedId = null;

  try {
    for (let i = 0; i < stagedFiles.length; i++) {
      const file = stagedFiles[i];
      const percent = Math.round(((i) / stagedFiles.length) * 100);

      if (progressBar) progressBar.style.width = `${percent}%`;
      if (progressPercent) progressPercent.textContent = `${percent}%`;
      if (progressLabel) progressLabel.textContent = `Analyzing ${file.name}...`;

      // Call single HTTP endpoint
      const result = await analyze(file);
      completedId = result.id;
    }

    // Complete progress
    if (progressBar) progressBar.style.width = '100%';
    if (progressPercent) progressPercent.textContent = '100%';
    if (progressLabel) progressLabel.textContent = 'Forensics complete! Loading report...';

    showToast('Email parsed and analyzed successfully!', 'success');

    // Redirect to the report page
    setTimeout(() => {
      if (completedId) {
        window.location.href = `report.html?id=${encodeURIComponent(completedId)}`;
      } else {
        window.location.href = 'index.html';
      }
    }, 600);

  } catch (err) {
    isUploading = false;
    if (startBtn) startBtn.disabled = false;
    if (dropZone) dropZone.classList.remove('uploading');
    if (progressWrapper) progressWrapper.classList.add('d-none');

    if (errorContainer) {
      showErrorBanner(
        errorContainer,
        `Analysis failed: ${err.message || 'An unexpected error occurred during triage.'}`
      );
    }
  }
}
