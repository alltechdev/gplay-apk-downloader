    const $ = s => document.querySelector(s);

    let downloadEventSource = null;
    let mergeEventSource = null;
    let currentDownloadInfo = null;
    let logCount = 0;
    let logActive = false;

    // --- SSE timeout helper ---
    const SSE_TIMEOUT = 300000; // 5 minutes
    function resetSseTimeout(cb, prev) {
      if (prev) clearTimeout(prev.id);
      return { id: setTimeout(cb, SSE_TIMEOUT), cb: cb };
    }

    // --- Log system ---
    const LOG_ICONS = {
      info: '\u2022', ok: '\u2713', err: '\u2717', warn: '\u25B3', dl: '\u2193'
    };

    function log(msg, type = 'info') {
      const scroll = $('#log-scroll');
      const empty = $('#log-empty');
      if (empty) empty.remove();

      const entry = document.createElement('div');
      entry.className = 'log-entry';
      const now = new Date();
      const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
      entry.innerHTML = '<span class="log-time">' + time + '</span>' +
        '<span class="log-icon ' + type + '">' + (LOG_ICONS[type] || LOG_ICONS.info) + '</span>' +
        '<span class="log-msg">' + esc(msg) + '</span>';
      scroll.appendChild(entry);
      scroll.scrollTop = scroll.scrollHeight;

      logCount++;
      const badge = $('#log-badge');
      badge.textContent = logCount;
      badge.classList.remove('empty');
    }

    function setLogActive(active) {
      logActive = active;
      $('#log-dot').style.display = active ? 'block' : 'none';
    }

    function clearLog() {
      const scroll = $('#log-scroll');
      scroll.innerHTML = '<div class="log-empty" id="log-empty">No activity yet</div>';
      logCount = 0;
      const badge = $('#log-badge');
      badge.textContent = '0';
      badge.classList.add('empty');
      setLogActive(false);
    }

    function toggleLog() {
      $('#log-panel').classList.toggle('open');
    }

    function clearDownloadState() {
      if (downloadEventSource) { downloadEventSource.close(); downloadEventSource = null; }
      if (mergeEventSource) { mergeEventSource.close(); mergeEventSource = null; }
      currentDownloadInfo = null;
      setLogActive(false);
    }

    document.addEventListener('DOMContentLoaded', () => {
      $('#arch-select').addEventListener('change', () => {
        clearDownloadState();
        $('#info-result').innerHTML = '';
        log('Architecture changed to ' + $('#arch-select').value, 'info');
      });
      refreshCounter();
      initAdb();
      // Always show import option (backup button shows when ADB connected)
      $('#backup-card').classList.add('visible');
    });

    function updateCounter(count) {
      if (count > 0) {
        $('#stat-counter').innerHTML = '<span>' + count.toLocaleString() + '</span> APKs downloaded';
      }
    }

    function refreshCounter() {
      fetch('/api/stats').then(r => r.json()).then(d => {
        updateCounter(d.downloads);
      }).catch(() => {});
    }

    // --- ADB ---
    let adbDeviceInfo = null;

    function initAdb() {
      const card = $('#adb-card');
      if (!navigator.usb) {
        $('#adb-status').innerHTML = '<span class="adb-unsupported">WebUSB requires Chrome or Edge</span>';
        return;
      }
      const isSecure = location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
      if (!isSecure) {
        $('#adb-status').innerHTML = '<span class="adb-unsupported">WebUSB requires HTTPS</span>';
        return;
      }

      // Merge tooltip when disabled
      const mergeLabel = $('#merge-label');
      const tooltip = document.createElement('div');
      tooltip.className = 'merge-tooltip';
      tooltip.textContent = 'ADB installs splits directly — no merge needed, original signatures preserved';
      mergeLabel.appendChild(tooltip);
      mergeLabel.addEventListener('click', (e) => {
        if ($('#merge-apks').disabled) {
          e.preventDefault();
          tooltip.classList.add('show');
          setTimeout(() => tooltip.classList.remove('show'), 3000);
        }
      });

      // Auto-reconnect cached device
      const cached = localStorage.getItem('adbDevice');
      if (cached) {
        navigator.usb.getDevices().then(devices => {
          if (devices.length > 0) adbConnect(true);
        }).catch(() => {});
      }

      // Listen for USB disconnect
      navigator.usb.addEventListener('disconnect', (e) => {
        if (window.adbManager?.connected && window.adbManager.device?.raw === e.device) {
          window.adbManager.disconnect();
          adbDeviceInfo = null;
          updateAdbUI('disconnected');
          log('ADB device disconnected', 'warn');
        }
      });
    }

    async function adbConnect(silent) {
      const statusEl = $('#adb-status');
      if (!window.adbManager) {
        if (!silent) log('ADB libraries still loading, try again in a moment', 'warn');
        return;
      }
      statusEl.innerHTML = '<span class="spinner"></span><span style="font-size:12px;color:var(--text-secondary)">Connecting... tap "Allow" on your device</span>';
      try {
        adbDeviceInfo = await window.adbManager.connect();
        updateAdbUI('connected');
        refreshInstallButton();
        log('ADB connected: ' + adbDeviceInfo.model + ' (Android ' + adbDeviceInfo.android + ')', 'ok');
      } catch (e) {
        adbDeviceInfo = null;
        updateAdbUI('disconnected');
        const msg = e.message || String(e);
        if (!silent) {
          if (msg.includes('No device') || msg.includes('cancelled')) {
            log('No device selected. Make sure USB debugging is enabled and plug in your phone.', 'warn');
          } else if (msg.includes('Unable to claim')) {
            log('USB device is in use by another app. Close other ADB connections first.', 'err');
          } else {
            log('ADB connection failed: ' + msg, 'err');
          }
        }
      }
    }

    async function adbDisconnect() {
      await window.adbManager?.disconnect();
      adbDeviceInfo = null;
      updateAdbUI('disconnected');
      refreshInstallButton();
      localStorage.removeItem('adbDevice');
      log('ADB disconnected', 'info');
    }

    let mergeWasChecked = true;

    function updateAdbUI(state) {
      const card = $('#adb-card');
      const statusEl = $('#adb-status');
      const mergeCheckbox = $('#merge-apks');
      if (state === 'connected' && adbDeviceInfo) {
        card.classList.add('connected');
        mergeWasChecked = mergeCheckbox.checked;
        mergeCheckbox.checked = false;
        mergeCheckbox.disabled = true;
        const backupBtn = $('#backup-btn');
        if (backupBtn) backupBtn.style.display = '';
        statusEl.innerHTML =
          '<div class="adb-dot"></div>' +
          '<div class="adb-device-name">' + esc(adbDeviceInfo.model) + '<small>Android ' + esc(adbDeviceInfo.android) + '</small></div>' +
          '<button class="btn-ghost" onclick="adbDisconnect()">Disconnect</button>';
      } else {
        card.classList.remove('connected');
        mergeCheckbox.disabled = false;
        mergeCheckbox.checked = mergeWasChecked;
        const backupBtn2 = $('#backup-btn');
        if (backupBtn2) backupBtn2.style.display = 'none';
        statusEl.innerHTML =
          '<button class="btn-secondary" onclick="adbConnect()">' +
          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 2v4M17 2v4M2 12h4M18 12h4M4.93 4.93l2.83 2.83M16.24 4.93l-2.83 2.83M12 8v4M12 16v.01"/><circle cx="12" cy="12" r="6"/></svg>' +
          'Connect Device</button>';
      }
    }

    function refreshInstallButton() {
      if (!currentDownloadInfo) return;
      const actions = document.querySelector('#info-result .app-actions');
      if (!actions) return;
      const existing = actions.querySelector('.btn-install');
      if (window.adbManager?.connected && !existing) {
        const btn = document.createElement('button');
        btn.className = 'btn-install';
        btn.onclick = installToDevice;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>Install to Device';
        actions.appendChild(btn);
      } else if (!window.adbManager?.connected && existing) {
        existing.remove();
      }
    }

    // --- Shared fetch helper ---
    async function fetchApkFile(directUrl, proxyUrl) {
      try {
        const resp = await fetch(directUrl);
        if (resp.ok) return resp.blob();
      } catch(e) { /* fall through */ }
      const resp = await fetch(proxyUrl);
      if (!resp.ok) throw new Error('Download failed');
      return resp.blob();
    }

    async function installToDevice() {
      if (!currentDownloadInfo || !window.adbManager?.connected) return;
      const { pkg, filename, versionCode, splits, downloadUrl } = currentDownloadInfo;
      const hasSplits = splits?.length > 0;
      const progressEl = $('#download-progress');
      const totalFiles = 1 + (splits?.length || 0);
      let downloaded = 0;

      if (!$('#log-panel').classList.contains('open')) toggleLog();
      setLogActive(true);
      log('Installing ' + pkg + ' to ' + (adbDeviceInfo?.model || 'device') + '...', 'dl');
      progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Downloading APK' + (hasSplits ? 's' : '') + '...<div class="progress" style="margin-top:8px"><div class="progress-bar" id="install-bar" style="width:0%"></div></div></div>';

      try {
        const apks = [];

        // Download base
        log('Downloading base APK: ' + filename, 'dl');
        const baseBlob = await fetchApkFile(downloadUrl, '/download/' + encodeURIComponent(pkg));
        apks.push({ blob: baseBlob, name: filename, size: baseBlob.size });
        downloaded++;
        updateInstallProgress(downloaded, totalFiles, 'download');
        log('Base APK downloaded (' + formatSize(baseBlob.size) + ')', 'ok');

        // Download splits
        for (let i = 0; i < (splits || []).length; i++) {
          log('Downloading split: ' + splits[i].filename, 'dl');
          const splitBlob = await fetchApkFile(splits[i].downloadUrl, '/download/' + encodeURIComponent(pkg) + '/' + i);
          apks.push({ blob: splitBlob, name: splits[i].filename, size: splitBlob.size });
          downloaded++;
          updateInstallProgress(downloaded, totalFiles, 'download');
          log('Split downloaded: ' + splits[i].filename + ' (' + formatSize(splitBlob.size) + ')', 'ok');
        }

        // Install
        progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Installing to device...<div class="progress progress-indeterminate" style="margin-top:8px"><div class="progress-bar"></div></div></div>';

        if (hasSplits) {
          await window.adbManager.installSplit(apks, (step, msg) => {
            log(msg, step === 'commit' ? 'info' : 'dl');
            progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>' + esc(msg) + '<div class="progress progress-indeterminate" style="margin-top:8px"><div class="progress-bar"></div></div></div>';
          });
        } else {
          log('Pushing APK to device...', 'dl');
          await window.adbManager.installSingle(apks[0].blob, apks[0].name);
        }

        setLogActive(false);
        log('Installed ' + pkg + ' successfully!', 'ok');
        progressEl.innerHTML = '<div class="msg ok fade-in">Installed to device</div>';
        fetch('/api/stats/increment', { method: 'POST' }).then(r => r.json()).then(d => updateCounter(d.downloads)).catch(() => {});
      } catch (e) {
        setLogActive(false);
        log('Install failed: ' + e.message, 'err');
        progressEl.innerHTML = '<div class="msg err fade-in">' + esc(e.message) + '</div>';
      }
    }

    function updateInstallProgress(current, total, phase) {
      const pct = Math.round((current / total) * 100);
      const barEl = $('#install-bar');
      if (barEl) barEl.style.width = pct + '%';
    }

    // --- Backup & Restore ---
    let backupData = null;

    async function backupApps() {
      if (!window.adbManager?.connected) {
        log('Connect a device first to backup app list', 'warn');
        return;
      }
      const resultEl = $('#backup-result');
      if (!$('#log-panel').classList.contains('open')) toggleLog();
      setLogActive(true);
      log('Reading installed packages from device...', 'dl');
      resultEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Reading installed packages...</div>';

      try {
        const output = await window.adbManager.shell('pm list packages -3');
        const packages = output.split('\n')
          .map(l => l.replace('package:', '').trim())
          .filter(p => p.length > 0)
          .sort();

        log('Found ' + packages.length + ' user-installed packages', 'ok');
        log('Checking availability on Google Play...', 'info');
        resultEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Checking ' + packages.length + ' packages on Google Play...<div class="progress" style="margin-top:8px"><div class="progress-bar" id="backup-bar" style="width:0%"></div></div></div>';

        const results = [];
        const BATCH_SIZE = 5;
        for (let i = 0; i < packages.length; i += BATCH_SIZE) {
          const batch = packages.slice(i, i + BATCH_SIZE);
          const batchResults = await Promise.all(batch.map(async function(pkg) {
            try {
              const info = await fetch('/api/info/' + encodeURIComponent(pkg)).then(r => r.json());
              if (info.error) {
                log(pkg + ' — not on Play Store', 'warn');
                return { package: pkg, available: false };
              } else {
                log(pkg + ' — ' + info.title, 'ok');
                return { package: pkg, available: true, title: info.title, developer: info.developer };
              }
            } catch {
              log(pkg + ' — check failed', 'warn');
              return { package: pkg, available: false };
            }
          }));
          results.push(...batchResults);
          const pct = Math.round(Math.min(i + BATCH_SIZE, packages.length) / packages.length * 100);
          const bar = $('#backup-bar');
          if (bar) bar.style.width = pct + '%';
        }

        const available = results.filter(r => r.available);
        const unavailable = results.filter(r => !r.available);
        backupData = { device: adbDeviceInfo?.model || 'Unknown', date: new Date().toISOString(), packages: results };

        setLogActive(false);
        log('Backup complete: ' + available.length + ' available on Play Store, ' + unavailable.length + ' not found', 'ok');

        let html = '<div class="backup-summary">' + available.length + ' available on Play Store, ' + unavailable.length + ' not found' +
          ' &middot; <a href="#" onclick="toggleAllBackupChecks(true);return false" style="color:var(--accent)">Select all</a>' +
          ' / <a href="#" onclick="toggleAllBackupChecks(false);return false" style="color:var(--accent)">None</a></div>';
        html += '<div class="backup-list">';
        for (const r of results) {
          html += '<div class="backup-item">' +
            '<input type="checkbox" class="backup-check" data-pkg="' + esc(r.package) + '"' + (r.available ? ' checked' : ' disabled') + '>' +
            '<span class="pkg-name" title="' + esc(r.package) + '">' + (r.title ? esc(r.title) + ' <span style="opacity:0.5">(' + esc(r.package) + ')</span>' : esc(r.package)) + '</span>' +
            '<span class="pkg-status ' + (r.available ? 'available' : 'unavailable') + '">' + (r.available ? 'available' : 'not found') + '</span>' +
            '</div>';
        }
        html += '</div>';
        html += '<div class="backup-actions">';
        html += '<button class="btn-primary" onclick="exportBackup()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>Export JSON</button>';
        if (available.length > 0) {
          html += '<button class="' + (window.adbManager?.connected ? 'btn-install' : 'btn-primary') + '" onclick="restoreSelected()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>' + (window.adbManager?.connected ? 'Restore to Device' : 'Download All') + '</button>';
        }
        html += '</div>';
        resultEl.innerHTML = html;
      } catch (e) {
        setLogActive(false);
        log('Backup failed: ' + e.message, 'err');
        resultEl.innerHTML = '<div class="msg err fade-in">' + esc(e.message) + '</div>';
      }
    }

    function exportBackup() {
      if (!backupData) return;
      const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'app-backup-' + new Date().toISOString().slice(0, 10) + '.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      log('Backup exported as ' + a.download, 'ok');
    }

    async function importBackup(event) {
      const file = event.target.files[0];
      if (!file) return;
      event.target.value = '';
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        if (!data.packages || !Array.isArray(data.packages)) throw new Error('Invalid backup file');
        backupData = data;
        const available = data.packages.filter(r => r.available);
        log('Imported backup: ' + data.packages.length + ' packages (' + available.length + ' available)', 'ok');

        const resultEl = $('#backup-result');
        let html = '<div class="backup-summary">From: ' + esc(data.device || 'Unknown') + ' &middot; ' + (data.date ? new Date(data.date).toLocaleDateString() : 'Unknown date') + ' &middot; ' + available.length + ' available' +
          ' &middot; <a href="#" onclick="toggleAllBackupChecks(true);return false" style="color:var(--accent)">Select all</a>' +
          ' / <a href="#" onclick="toggleAllBackupChecks(false);return false" style="color:var(--accent)">None</a></div>';
        html += '<div class="backup-list">';
        for (const r of data.packages.filter(r => r.available)) {
          html += '<div class="backup-item">' +
            '<input type="checkbox" class="backup-check" data-pkg="' + esc(r.package) + '" checked>' +
            '<span class="pkg-name">' + (r.title ? esc(r.title) + ' <span style="opacity:0.5">(' + esc(r.package) + ')</span>' : esc(r.package)) + '</span>' +
            '<span class="pkg-status available">available</span>' +
            '</div>';
        }
        html += '</div>';
        html += '<div class="backup-actions">';
        html += '<button class="' + (window.adbManager?.connected ? 'btn-install' : 'btn-primary') + '" onclick="restoreSelected()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>' + (window.adbManager?.connected ? 'Restore to Device' : 'Download All') + '</button>';
        html += '</div>';
        resultEl.innerHTML = html;
      } catch (e) {
        log('Import failed: ' + e.message, 'err');
        $('#backup-result').innerHTML = '<div class="msg err fade-in">Invalid backup file: ' + esc(e.message) + '</div>';
      }
    }

    function toggleAllBackupChecks(checked) {
      document.querySelectorAll('.backup-check:not(:disabled)').forEach(function(c) { c.checked = checked; });
    }

    let restoreAborted = false;

    function abortRestore() {
      restoreAborted = true;
      log('Abort requested — stopping after current app...', 'warn');
    }

    async function restoreSelected() {
      const checks = document.querySelectorAll('.backup-check:checked');
      const packages = Array.from(checks).map(c => c.dataset.pkg);
      if (packages.length === 0) { log('No packages selected', 'warn'); return; }

      const useAdb = window.adbManager?.connected;
      const arch = $('#arch-select').value;
      const resultEl = $('#backup-result');
      restoreAborted = false;

      // Disable all backup action buttons during restore
      document.querySelectorAll('#backup-result button, #backup-actions button').forEach(function(b) { b.disabled = true; });

      if (!$('#log-panel').classList.contains('open')) toggleLog();
      setLogActive(true);
      const action = useAdb ? 'Restoring' : 'Downloading';
      log(action + ' ' + packages.length + ' apps' + (useAdb ? ' to ' + (adbDeviceInfo?.model || 'device') : '') + '...', 'dl');

      let succeeded = 0, failed = 0;

      for (let i = 0; i < packages.length; i++) {
        // Check abort flag
        if (restoreAborted) {
          log('Restore aborted by user (' + succeeded + ' completed, ' + (packages.length - i) + ' skipped)', 'warn');
          break;
        }

        // Abort if ADB was disconnected mid-restore
        if (useAdb && !window.adbManager?.connected) {
          log('Device disconnected — aborting restore (' + succeeded + ' completed)', 'err');
          resultEl.innerHTML = '<div class="msg err fade-in">Device disconnected. ' + succeeded + ' apps installed before disconnect.</div>';
          setLogActive(false);
          refreshCounter();
          return;
        }

        const pkg = packages[i];
        const pct = Math.round(((i + 1) / packages.length) * 100);
        resultEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>' + (useAdb ? 'Restoring' : 'Downloading') + ' ' + (i + 1) + '/' + packages.length + ': ' + esc(pkg) +
          '<div class="progress" style="margin-top:8px"><div class="progress-bar" style="width:' + pct + '%"></div></div>' +
          '<button class="btn-secondary" onclick="abortRestore()" style="margin-top:8px;font-size:11px">Abort</button></div>';

        try {
          log('(' + (i + 1) + '/' + packages.length + ') Getting download info for ' + pkg + '...', 'dl');

          // Get download info via SSE
          const dlInfo = await new Promise((resolve, reject) => {
            const cacheBuster = Date.now();
            const url = '/api/download-info-stream/' + encodeURIComponent(pkg) + '?arch=' + arch + '&_=' + cacheBuster;
            const es = new EventSource(url);
            const timeout = setTimeout(() => { es.close(); reject(new Error('Timeout')); }, 120000);
            es.onmessage = function(event) {
              const d = JSON.parse(event.data);
              if (d.type === 'success') { clearTimeout(timeout); es.close(); resolve(d); }
              else if (d.type === 'error') { clearTimeout(timeout); es.close(); reject(new Error(d.message)); }
              else if (d.type === 'progress') { log('  Token attempt #' + d.attempt + ': ' + d.message, 'info'); }
            };
            es.onerror = function() { clearTimeout(timeout); es.close(); reject(new Error('Connection lost')); };
          });

          if (useAdb) {
            // Download and install via ADB
            const hasSplits = dlInfo.splits?.length > 0;
            const apks = [];

            log('  Downloading base APK...', 'dl');
            const baseBlob = await fetchApkFile(dlInfo.downloadUrl, '/download/' + encodeURIComponent(pkg));
            apks.push({ blob: baseBlob, name: dlInfo.filename, size: baseBlob.size });

            for (let j = 0; j < (dlInfo.splits || []).length; j++) {
              log('  Downloading split: ' + dlInfo.splits[j].filename + '...', 'dl');
              const splitBlob = await fetchApkFile(dlInfo.splits[j].downloadUrl, '/download/' + encodeURIComponent(pkg) + '/' + j);
              apks.push({ blob: splitBlob, name: dlInfo.splits[j].filename, size: splitBlob.size });
            }

            if (hasSplits) {
              await window.adbManager.installSplit(apks, (step, msg) => log('  ' + msg, 'dl'));
            } else {
              log('  Installing to device...', 'dl');
              await window.adbManager.installSingle(apks[0].blob, apks[0].name);
            }
            log(pkg + ' installed successfully', 'ok');
            fetch('/api/stats/increment', { method: 'POST' }).catch(() => {});
          } else {
            // Download merged via server — use hidden iframe to avoid navigating away
            log('  Downloading ' + pkg + '...', 'dl');
            const downloadId = await new Promise((resolve, reject) => {
              const url = '/api/download-merged-stream/' + encodeURIComponent(pkg) + '?arch=' + arch + '&_=' + Date.now();
              const es = new EventSource(url);
              const timeout = setTimeout(() => { es.close(); reject(new Error('Timeout')); }, 300000);
              es.onmessage = function(event) {
                const d = JSON.parse(event.data);
                if (d.type === 'success') {
                  clearTimeout(timeout); es.close();
                  if (d.downloads) updateCounter(d.downloads);
                  resolve(d.download_id);
                } else if (d.type === 'error') { clearTimeout(timeout); es.close(); reject(new Error(d.message)); }
                else if (d.type === 'progress') { log('  ' + d.message, 'dl'); }
              };
              es.onerror = function() { clearTimeout(timeout); es.close(); reject(new Error('Connection lost')); };
            });
            // Trigger download via hidden iframe instead of window.location.href
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = '/api/download-temp/' + downloadId;
            document.body.appendChild(iframe);
            setTimeout(function() { iframe.remove(); }, 30000);
            log(pkg + ' download complete', 'ok');
          }
          succeeded++;
        } catch (e) {
          failed++;
          log(pkg + ' failed: ' + e.message, 'err');
        }
      }

      setLogActive(false);
      const abortedCount = restoreAborted ? packages.length - succeeded - failed : 0;
      let summary = succeeded + ' succeeded, ' + failed + ' failed';
      if (abortedCount > 0) summary += ', ' + abortedCount + ' skipped';
      const doneLabel = useAdb ? 'Restore' : 'Download';
      log(doneLabel + ' complete: ' + summary, succeeded > 0 ? 'ok' : 'err');
      resultEl.innerHTML = '<div class="msg ' + (failed === 0 ? 'ok' : 'err') + ' fade-in">' + doneLabel + ' complete: ' + summary + '</div>';
      refreshCounter();
    }

    function formatSize(bytes) {
      if (bytes > 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
      if (bytes > 1024) return (bytes / 1024).toFixed(0) + ' KB';
      return bytes + ' B';
    }

    async function search() {
      const q = $('#search-q').value.trim();
      if (!q) return;
      const el = $('#search-results');
      el.innerHTML = '<div class="loading fade-in"><span class="spinner"></span>Searching...</div>';
      log('Searching for "' + q + '"...', 'info');
      try {
        const d = await fetch('/api/search?q=' + encodeURIComponent(q)).then(r => r.json());
        if (d.error) { el.innerHTML = '<div class="msg err fade-in">' + esc(d.error) + '</div>'; log('Search error: ' + d.error, 'err'); return; }
        if (!d.results?.length) { el.innerHTML = '<div class="msg info fade-in">No results found</div>'; log('No results for "' + q + '"', 'warn'); return; }
        log('Found ' + d.results.length + ' results for "' + q + '"', 'ok');
        el.innerHTML = d.results.map(a =>
          '<div class="app-item fade-in">' +
          (a.icon ? '<img class="app-icon" src="' + esc(a.icon) + '" alt="" loading="lazy">' : '') +
          '<div class="app-info"><h3>' + esc(a.title || a.package) + '</h3><div class="pkg">' + esc(a.package) + '</div></div>' +
          '<div class="app-actions"><button class="btn-primary" onclick="dl(\'' + esc(a.package) + '\')">Download</button></div></div>'
        ).join('');
      } catch(e) { el.innerHTML = '<div class="msg err fade-in">' + esc(String(e)) + '</div>'; log('Search failed: ' + e, 'err'); }
    }

    function esc(s) {
      const d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML.replace(/'/g, '&#39;');
    }

    function sel(pkg) { $('#pkg-input').value = pkg; getInfo(); }

    async function getInfo() {
      const pkg = $('#pkg-input').value.trim();
      if (!pkg) return;
      const el = $('#info-result');
      el.innerHTML = '<div class="loading fade-in"><span class="spinner"></span>Fetching app info...</div>';
      log('Fetching info for ' + pkg, 'info');
      try {
        const d = await fetch('/api/info/' + encodeURIComponent(pkg)).then(r => r.json());
        if (d.error) { el.innerHTML = '<div class="msg err fade-in">' + esc(d.error) + '</div>'; log('Info error: ' + d.error, 'err'); return; }
        log('Got info: ' + d.title + ' by ' + d.developer, 'ok');
        el.innerHTML = '<div class="app-item fade-in"><div class="app-info"><h3>' + esc(d.title) + '</h3><div class="pkg">' + esc(d.package) + '</div><div class="pkg" style="margin-top:2px">by ' + esc(d.developer) + '</div></div><div class="app-actions"><button class="btn-primary" onclick="dl(\'' + esc(d.package) + '\')">Download</button></div></div>';
      } catch(e) { el.innerHTML = '<div class="msg err fade-in">' + esc(String(e)) + '</div>'; log('Info failed: ' + e, 'err'); }
    }

    function download() {
      const pkg = $('#pkg-input').value.trim();
      if (!pkg) return;
      dl(pkg);
    }

    function stopDownload() {
      clearDownloadState();
      $('#info-result').innerHTML = '<div class="msg info fade-in">Download cancelled</div>';
      log('Download cancelled by user', 'warn');
    }

    async function dl(pkg) {
      clearDownloadState();
      $('#info-result').innerHTML = '';
      const el = $('#info-result');
      const arch = $('#arch-select').value;
      const shouldMerge = $('#merge-apks').checked;
      const archLabel = arch === 'arm64-v8a' ? 'ARM64' : 'ARMv7';

      // Open log panel automatically
      if (!$('#log-panel').classList.contains('open')) toggleLog();
      setLogActive(true);
      log('Starting download for ' + pkg + ' (' + archLabel + ')', 'dl');

      el.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Preparing download (' + archLabel + ')...' +
        '<div style="margin-top:8px"><button class="btn-ghost" onclick="stopDownload()">Cancel</button></div>' +
        '<div class="progress progress-indeterminate" style="margin-top:8px"><div class="progress-bar"></div></div></div>';

      const cacheBuster = Date.now();
      const url = '/api/download-info-stream/' + encodeURIComponent(pkg) + '?arch=' + arch + '&_=' + cacheBuster;
      log('Connecting to token stream...', 'info');
      downloadEventSource = new EventSource(url);

      // Auto-timeout after 5 min of no messages
      let dlTimeout = resetSseTimeout(function() {
        if (downloadEventSource) {
          downloadEventSource.close(); downloadEventSource = null;
          setLogActive(false);
          log('Token acquisition timed out (5 min no response)', 'err');
          el.innerHTML = '<div class="msg err fade-in">Timed out. Please try again.</div>';
        }
      });

      downloadEventSource.onmessage = function(event) {
        dlTimeout = resetSseTimeout(dlTimeout.cb, dlTimeout);
        const d = JSON.parse(event.data);

        if (d.type === 'progress') {
          log('Token attempt #' + d.attempt + ': ' + d.message, 'info');
          el.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>' + esc(d.message) +
            '<div style="margin-top:4px;font-size:11px;opacity:0.6;font-family:var(--font-mono)">Attempt #' + d.attempt + '</div>' +
            '<div style="margin-top:8px"><button class="btn-ghost" onclick="stopDownload()">Cancel</button></div>' +
            '<div class="progress progress-indeterminate" style="margin-top:8px"><div class="progress-bar"></div></div></div>';
        } else if (d.type === 'error') {
          downloadEventSource.close();
          downloadEventSource = null;
          setLogActive(false);
          log('Error: ' + d.message, 'err');
          el.innerHTML = '<div class="msg err fade-in">' + esc(d.message) + '</div>';
        } else if (d.type === 'success') {
          downloadEventSource.close();
          downloadEventSource = null;
          setLogActive(false);
          currentDownloadInfo = { pkg, arch, ...d };
          const hasSplits = d.splits?.length > 0;
          const totalFiles = 1 + (d.splits?.length || 0);
          const splitNames = d.splits ? d.splits.map(s => s.name).join(', ') : 'none';

          log('Token acquired after ' + d.attempt + ' attempts', 'ok');
          log('App: ' + d.title + ' v' + d.version + ' (' + d.size + ')', 'ok');
          if (hasSplits) log('Split APKs: ' + splitNames, 'info');
          log('Ready to download' + (hasSplits && shouldMerge ? ' (will merge ' + totalFiles + ' splits)' : ''), 'ok');

          let html = '<div class="msg ok fade-in"><strong>' + esc(d.title) + '</strong><br>v' + esc(d.version) + ' &middot; ' + archLabel + ' &middot; ' + esc(d.size);
          if (hasSplits) {
            html += '<br><span style="font-family:var(--font-mono);font-size:11px;opacity:0.7">' + totalFiles + ' files: ' + esc(splitNames) + '</span>';
          }
          html += '</div>';

          html += '<div class="app-item fade-in"><div class="app-info">';
          if (hasSplits && shouldMerge) {
            html += '<h3>Merged APK</h3><div class="pkg">Single installable APK from ' + totalFiles + ' splits</div>';
          } else if (hasSplits) {
            html += '<h3>All APKs (' + totalFiles + ')</h3><div class="pkg">Base + splits bundled as ZIP</div>';
          } else {
            html += '<h3>Download APK</h3><div class="pkg">' + esc(d.filename) + '</div>';
          }
          html += '</div><div class="app-actions">';
          if (hasSplits && shouldMerge) {
            html += '<button class="btn-primary" onclick="downloadMerged(\'' + esc(pkg) + '\')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download</button>';
          } else if (hasSplits) {
            html += '<button class="btn-primary" onclick="downloadAll()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download ZIP</button>';
          } else {
            html += '<a href="' + esc(d.downloadUrl) + '" download="' + esc(d.filename) + '"><button class="btn-primary"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download</button></a>';
          }
          if (window.adbManager?.connected) {
            html += '<button class="btn-install" onclick="installToDevice()">' +
              '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>' +
              'Install to Device</button>';
          }
          html += '</div></div><div id="download-progress"></div>';
          el.innerHTML = html;
        }
      };

      downloadEventSource.onerror = function() {
        clearTimeout(dlTimeout.id);
        downloadEventSource.close();
        downloadEventSource = null;
        setLogActive(false);
        log('Connection lost during token acquisition', 'err');
        el.innerHTML = '<div class="msg err fade-in">Connection lost. Please try again.</div>';
      };
    }

    function downloadMerged(pkg) {
      if (mergeEventSource) { mergeEventSource.close(); mergeEventSource = null; }
      const arch = $('#arch-select').value;
      const archLabel = arch === 'arm64-v8a' ? 'ARM64' : 'ARMv7';
      const progressEl = $('#download-progress');
      setLogActive(true);
      log('Starting download & merge for ' + pkg + ' (' + archLabel + ')', 'dl');
      progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Starting merge (' + archLabel + ')...<div class="progress progress-indeterminate" style="margin-top:8px"><div class="progress-bar"></div></div></div>';

      const cacheBuster = Date.now();
      const url = '/api/download-merged-stream/' + encodeURIComponent(pkg) + '?arch=' + arch + '&_=' + cacheBuster;
      mergeEventSource = new EventSource(url);

      // Auto-timeout after 5 min of no messages
      let mergeTimeout = resetSseTimeout(function() {
        if (mergeEventSource) {
          mergeEventSource.close(); mergeEventSource = null;
          setLogActive(false);
          log('Merge operation timed out (5 min no response)', 'err');
          progressEl.innerHTML = '<div class="msg err fade-in">Timed out. Please try again.</div>';
        }
      });

      mergeEventSource.onmessage = function(event) {
        mergeTimeout = resetSseTimeout(mergeTimeout.cb, mergeTimeout);
        const d = JSON.parse(event.data);
        if (d.type === 'progress') {
          let pctText = '';
          let pct = '';
          if (d.current && d.total) {
            const pctVal = Math.round((d.current / d.total) * 100);
            pctText = ' (' + pctVal + '%)';
            pct = '<div class="progress" style="margin-top:8px"><div class="progress-bar" style="width:' + pctVal + '%"></div></div>';
          } else {
            pct = '<div class="progress progress-indeterminate" style="margin-top:8px"><div class="progress-bar"></div></div>';
          }
          log(d.message + pctText, 'dl');
          progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>' + esc(d.message) + pct + '</div>';
        } else if (d.type === 'success') {
          mergeEventSource.close();
          mergeEventSource = null;
          setLogActive(false);
          if (d.original) {
            log('Download complete - original signature preserved', 'ok');
            progressEl.innerHTML = '<div class="msg ok fade-in">Download complete &mdash; original signature preserved</div>';
          } else {
            log('Merge complete - triggering download', 'ok');
            progressEl.innerHTML = '<div class="msg ok fade-in">Merge complete &mdash; starting download...</div>';
          }
          window.location.href = '/api/download-temp/' + d.download_id;
          if (d.downloads) updateCounter(d.downloads);
        } else if (d.type === 'error') {
          mergeEventSource.close();
          mergeEventSource = null;
          setLogActive(false);
          log('Merge error: ' + d.message, 'err');
          progressEl.innerHTML = '<div class="msg err fade-in">' + esc(d.message) + '</div>';
        }
      };

      mergeEventSource.onerror = function() {
        clearTimeout(mergeTimeout.id);
        mergeEventSource.close();
        mergeEventSource = null;
        setLogActive(false);
        log('Connection lost during merge', 'err');
        progressEl.innerHTML = '<div class="msg err fade-in">Connection lost. Please try again.</div>';
      };
    }

    async function downloadAll() {
      if (!currentDownloadInfo) return;
      const { pkg, filename, versionCode, splits, downloadUrl } = currentDownloadInfo;
      const progressEl = $('#download-progress');
      const totalFiles = 1 + splits.length;
      let downloaded = 0;

      setLogActive(true);
      log('Starting ZIP download (' + totalFiles + ' files)', 'dl');
      progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Downloading <span id="dl-status">0/' + totalFiles + '</span><div class="progress" style="margin-top:8px"><div class="progress-bar" id="dl-bar" style="width:0%"></div></div></div>';

      try {
        const zip = new JSZip();

        log('Downloading base APK: ' + filename, 'dl');
        const baseBlob = await fetchApkFile(downloadUrl, '/download/' + encodeURIComponent(pkg));
        zip.file(filename, baseBlob);
        downloaded++;
        updateProgress(downloaded, totalFiles);
        log('Base APK downloaded (' + downloaded + '/' + totalFiles + ')', 'ok');

        for (let i = 0; i < splits.length; i++) {
          log('Downloading split: ' + splits[i].filename, 'dl');
          const splitBlob = await fetchApkFile(splits[i].downloadUrl, '/download/' + encodeURIComponent(pkg) + '/' + i);
          zip.file(splits[i].filename, splitBlob);
          downloaded++;
          updateProgress(downloaded, totalFiles);
          log('Split downloaded (' + downloaded + '/' + totalFiles + ')', 'ok');
        }

        log('Creating ZIP archive...', 'info');
        progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Creating ZIP...</div>';
        const zipBlob = await zip.generateAsync({ type: 'blob' });

        const url = URL.createObjectURL(zipBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = pkg + '-' + versionCode + '.zip';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        setLogActive(false);
        log('ZIP download complete: ' + pkg + '-' + versionCode + '.zip', 'ok');
        progressEl.innerHTML = '<div class="msg ok fade-in">Download complete</div>';
        fetch('/api/stats/increment', { method: 'POST' }).then(r => r.json()).then(d => updateCounter(d.downloads)).catch(() => {});
      } catch(e) {
        setLogActive(false);
        log('Download failed: ' + e.message, 'err');
        progressEl.innerHTML = '<div class="msg err fade-in">' + esc(e.message) + '</div>';
      }
    }

    function updateProgress(current, total) {
      const pct = Math.round((current / total) * 100);
      const statusEl = $('#dl-status');
      const barEl = $('#dl-bar');
      if (statusEl) statusEl.textContent = current + '/' + total;
      if (barEl) barEl.style.width = pct + '%';
    }
