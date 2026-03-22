    console.log('[app-page.js] loaded');
    const $ = s => document.querySelector(s);



    let downloadEventSource = null;

    // --- ADB ---
    let adbDeviceInfo = null;
    let mergeWasChecked = true;

    // Init ADB - handle both cases: DOM already loaded or still loading
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function() { initAdb(); });
    } else {
      initAdb();
    }

    function initAdb() {
      if (!navigator.usb) {
        $('#adb-status').innerHTML = '<span class="adb-unsupported">WebUSB requires Chrome or Edge</span>';
        return;
      }
      var isSecure = location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
      if (!isSecure) {
        $('#adb-status').innerHTML = '<span class="adb-unsupported">WebUSB requires HTTPS</span>';
        return;
      }
      const mergeLabel = $('#merge-label');
      if (mergeLabel) {
        const tooltip = document.createElement('div');
        tooltip.className = 'merge-tooltip';
        tooltip.textContent = 'ADB installs splits directly — no merge needed, original signatures preserved';
        mergeLabel.appendChild(tooltip);
        mergeLabel.addEventListener('click', function(e) {
          if ($('#merge-apks').disabled) {
            e.preventDefault();
            tooltip.classList.add('show');
            setTimeout(function() { tooltip.classList.remove('show'); }, 3000);
          }
        });
      }
      var cached = localStorage.getItem('adbDevice');
      if (cached) {
        navigator.usb.getDevices().then(function(devices) {
          if (devices.length > 0) adbConnect(true);
        }).catch(function() {});
      }
      navigator.usb.addEventListener('disconnect', function(e) {
        if (window.adbManager && window.adbManager.connected && window.adbManager.device && window.adbManager.device.raw === e.device) {
          window.adbManager.disconnect();
          adbDeviceInfo = null;
          updateAdbUI('disconnected');
          log('ADB device disconnected', 'warn');
        }
      });
    }

    async function adbConnect(silent) {
      var statusEl = $('#adb-status');
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
        var msg = e.message || String(e);
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
      if (window.adbManager) await window.adbManager.disconnect();
      adbDeviceInfo = null;
      updateAdbUI('disconnected');
      refreshInstallButton();
      localStorage.removeItem('adbDevice');
      log('ADB disconnected', 'info');
    }

    function updateAdbUI(state) {
      var card = $('#adb-card');
      var statusEl = $('#adb-status');
      var mergeCheckbox = $('#merge-apks');
      if (state === 'connected' && adbDeviceInfo) {
        card.classList.add('connected');
        mergeWasChecked = mergeCheckbox.checked;
        mergeCheckbox.checked = false;
        mergeCheckbox.disabled = true;
        statusEl.innerHTML =
          '<div class="adb-dot"></div>' +
          '<div class="adb-device-name">' + esc(adbDeviceInfo.model) + '<small>Android ' + esc(adbDeviceInfo.android) + '</small></div>' +
          '<button class="btn-ghost" onclick="adbDisconnect()">Disconnect</button>';
      } else {
        card.classList.remove('connected');
        mergeCheckbox.disabled = false;
        mergeCheckbox.checked = mergeWasChecked;
        statusEl.innerHTML =
          '<button class="btn-secondary" onclick="adbConnect()">' +
          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 2v4M17 2v4M2 12h4M18 12h4M4.93 4.93l2.83 2.83M16.24 4.93l-2.83 2.83M12 8v4M12 16v.01"/><circle cx="12" cy="12" r="6"/></svg>' +
          'Connect Device</button>';
      }
    }

    function refreshInstallButton() {
      if (!currentDownloadInfo) return;
      var actions = document.querySelector('#info-result .app-actions');
      if (!actions) return;
      var existing = actions.querySelector('.btn-install');
      if (window.adbManager && window.adbManager.connected && !existing) {
        var btn = document.createElement('button');
        btn.className = 'btn-install';
        btn.onclick = installToDevice;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>Install to Device';
        actions.appendChild(btn);
      } else if (!(window.adbManager && window.adbManager.connected) && existing) {
        existing.remove();
      }
    }

    async function installToDevice() {
      if (!currentDownloadInfo || !(window.adbManager && window.adbManager.connected)) return;
      var info = currentDownloadInfo;
      var hasSplits = info.splits && info.splits.length > 0;
      var progressEl = $('#download-progress');
      var totalFiles = 1 + (info.splits ? info.splits.length : 0);
      var downloaded = 0;

      if (!$('#log-panel').classList.contains('open')) toggleLog();
      setLogActive(true);
      log('Installing ' + info.pkg + ' to ' + (adbDeviceInfo ? adbDeviceInfo.model : 'device') + '...', 'dl');
      progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Downloading APK' + (hasSplits ? 's' : '') + '...<div class="progress" style="margin-top:8px"><div class="progress-bar" id="install-bar" style="width:0%"></div></div></div>';

      try {
        var apks = [];
        log('Downloading base APK: ' + info.filename, 'dl');
        var baseBlob = await fetchApkFile(info.downloadUrl, '/download/' + encodeURIComponent(info.pkg) + '?arch=' + encodeURIComponent($('#arch-select').value));
        apks.push({ blob: baseBlob, name: info.filename, size: baseBlob.size });
        downloaded++;
        var barEl = $('#install-bar');
        if (barEl) barEl.style.width = Math.round((downloaded / totalFiles) * 100) + '%';

        for (var i = 0; i < (info.splits || []).length; i++) {
          log('Downloading split: ' + info.splits[i].filename, 'dl');
          var splitBlob = await fetchApkFile(info.splits[i].downloadUrl, '/download/' + encodeURIComponent(info.pkg) + '/' + i + '?arch=' + encodeURIComponent($('#arch-select').value));
          apks.push({ blob: splitBlob, name: info.splits[i].filename, size: splitBlob.size });
          downloaded++;
          if (barEl) barEl.style.width = Math.round((downloaded / totalFiles) * 100) + '%';
        }

        progressEl.innerHTML = '<div class="msg info fade-in"><span class="spinner"></span>Installing to device...<div class="progress progress-indeterminate" style="margin-top:8px"><div class="progress-bar"></div></div></div>';
        if (hasSplits) {
          await window.adbManager.installSplit(apks, function(step, msg) {
            log(msg, step === 'commit' ? 'info' : 'dl');
          });
        } else {
          log('Pushing APK to device...', 'dl');
          await window.adbManager.installSingle(apks[0].blob, apks[0].name);
        }
        setLogActive(false);
        log('Installed ' + info.pkg + ' successfully!', 'ok');
        progressEl.innerHTML = '<div class="msg ok fade-in">Installed to device</div>';
        fetch('/api/stats/increment', { method: 'POST' }).catch(function() {});
      } catch (e) {
        setLogActive(false);
        log('Install failed: ' + e.message, 'err');
        progressEl.innerHTML = '<div class="msg err fade-in">' + esc(e.message) + '</div>';
      }
    }
    let mergeEventSource = null;
    let currentDownloadInfo = null;
    let logCount = 0;
    let logActive = false;

    const SSE_TIMEOUT = 300000;
    function resetSseTimeout(cb, prev) {
      if (prev) clearTimeout(prev.id);
      return { id: setTimeout(cb, SSE_TIMEOUT), cb: cb };
    }

    function esc(s) {
      const d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML.replace(/'/g, '&#39;');
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

    function toggleLog() { $('#log-panel').classList.toggle('open'); }

    function clearDownloadState() {
      if (downloadEventSource) { downloadEventSource.close(); downloadEventSource = null; }
      if (mergeEventSource) { mergeEventSource.close(); mergeEventSource = null; }
      currentDownloadInfo = null;
      setLogActive(false);
    }

    function stopDownload() {
      clearDownloadState();
      $('#info-result').innerHTML = '<div class="msg info fade-in">Download cancelled</div>';
      log('Download cancelled by user', 'warn');
    }

    async function fetchApkFile(directUrl, proxyUrl) {
      try {
        const resp = await fetch(directUrl);
        if (resp.ok) return resp.blob();
      } catch(e) { /* fall through */ }
      const resp = await fetch(proxyUrl);
      if (!resp.ok) throw new Error('Download failed');
      return resp.blob();
    }

    function updateProgress(current, total) {
      const pct = Math.round((current / total) * 100);
      const statusEl = $('#dl-status');
      const barEl = $('#dl-bar');
      if (statusEl) statusEl.textContent = current + '/' + total;
      if (barEl) barEl.style.width = pct + '%';
    }

    // --- Download flow ---
    async function dl(pkg) {
      clearDownloadState();
      $('#info-result').innerHTML = '';
      const el = $('#info-result');
      const arch = $('#arch-select').value;
      const shouldMerge = $('#merge-apks').checked;
      const archLabel = arch === 'arm64-v8a' ? 'ARM64' : 'ARMv7';

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
          downloadEventSource.close(); downloadEventSource = null;
          setLogActive(false);
          log('Error: ' + d.message, 'err');
          el.innerHTML = '<div class="msg err fade-in">' + esc(d.message) + '</div>';
        } else if (d.type === 'success') {
          downloadEventSource.close(); downloadEventSource = null;
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
            html += '<a href="/download/' + encodeURIComponent(pkg) + '?arch=' + encodeURIComponent(arch) + '"><button class="btn-primary"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download</button></a>';
          }
          html += '</div></div><div id="download-progress"></div>';
          el.innerHTML = html;
        }
      };

      downloadEventSource.onerror = function() {
        clearTimeout(dlTimeout.id);
        downloadEventSource.close(); downloadEventSource = null;
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
          mergeEventSource.close(); mergeEventSource = null;
          setLogActive(false);
          if (d.original) {
            log('Download complete - original signature preserved', 'ok');
            progressEl.innerHTML = '<div class="msg ok fade-in">Download complete &mdash; original signature preserved</div>';
          } else {
            log('Merge complete - triggering download', 'ok');
            progressEl.innerHTML = '<div class="msg ok fade-in">Merge complete &mdash; starting download...</div>';
          }
          window.location.href = '/api/download-temp/' + d.download_id;
          if (d.downloads) {
            const counter = $('#stat-counter');
            if (counter) counter.innerHTML = '<span>' + d.downloads.toLocaleString() + '</span> APKs downloaded';
          }
        } else if (d.type === 'error') {
          mergeEventSource.close(); mergeEventSource = null;
          setLogActive(false);
          log('Merge error: ' + d.message, 'err');
          progressEl.innerHTML = '<div class="msg err fade-in">' + esc(d.message) + '</div>';
        }
      };

      mergeEventSource.onerror = function() {
        clearTimeout(mergeTimeout.id);
        mergeEventSource.close(); mergeEventSource = null;
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
        const baseBlob = await fetchApkFile(downloadUrl, '/download/' + encodeURIComponent(pkg) + '?arch=' + encodeURIComponent($('#arch-select').value));
        zip.file(filename, baseBlob);
        downloaded++;
        updateProgress(downloaded, totalFiles);
        log('Base APK downloaded (' + downloaded + '/' + totalFiles + ')', 'ok');

        for (let i = 0; i < splits.length; i++) {
          log('Downloading split: ' + splits[i].filename, 'dl');
          const splitBlob = await fetchApkFile(splits[i].downloadUrl, '/download/' + encodeURIComponent(pkg) + '/' + i + '?arch=' + encodeURIComponent($('#arch-select').value));
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
        fetch('/api/stats/increment', { method: 'POST' }).catch(() => {});
      } catch(e) {
        setLogActive(false);
        log('Download failed: ' + e.message, 'err');
        progressEl.innerHTML = '<div class="msg err fade-in">Download failed: ' + esc(e.message) + '</div>';
      }
    }
