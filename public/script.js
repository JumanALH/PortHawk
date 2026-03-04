const scanForm = document.getElementById('scanForm');
const targetInput = document.getElementById('target');
const scanTypeSelect = document.getElementById('scanType');
const timeoutSelect = document.getElementById('timeout');
const customPortGroup = document.getElementById('customPortGroup');
const customPortsInput = document.getElementById('customPorts');
const concurrencySlider = document.getElementById('concurrency');
const concurrencyValue = document.getElementById('concurrencyValue');
const btnScan = document.getElementById('btnScan');
const progressSection = document.getElementById('progressSection');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const progressPorts = document.getElementById('progressPorts');
const liveFeed = document.getElementById('liveFeed');
const resultsSection = document.getElementById('resultsSection');
const summaryGrid = document.getElementById('summaryGrid');
const resultsBody = document.getElementById('resultsBody');
const recommendationsDiv = document.getElementById('recommendations');
const historyList = document.getElementById('historyList');
const securityScoreSection = document.getElementById('securityScoreSection');
const vulnSection = document.getElementById('vulnSection');
const btnNetDiscover = document.getElementById('btnNetDiscover');
const netDiscoverResults = document.getElementById('netDiscoverResults');

let currentScanId = null;

scanTypeSelect.addEventListener('change', () => {
  customPortGroup.style.display = scanTypeSelect.value === 'custom' ? 'block' : 'none';
});

concurrencySlider.addEventListener('input', () => {
  concurrencyValue.textContent = concurrencySlider.value;
});

scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  await startScan();
});

btnNetDiscover.addEventListener('click', () => {
  discoverNetwork();
});

async function startScan() {
  const target = targetInput.value.trim();
  if (!target) return;

  const scanType = scanTypeSelect.value;
  const timeout = parseInt(timeoutSelect.value);
  const concurrency = parseInt(concurrencySlider.value);

  const body = { target, timeout, concurrency };

  if (scanType === 'custom') {
    body.portRange = customPortsInput.value.trim();
    if (!body.portRange) {
      alert('Please enter a port range');
      return;
    }
  } else if (scanType === 'full') {
    body.portRange = '1-1024';
  } else {
    body.preset = scanType;
  }

  setScanning(true);
  progressSection.style.display = 'block';
  resultsSection.style.display = 'none';
  progressFill.style.width = '0%';
  progressText.textContent = '0%';
  liveFeed.innerHTML = '';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    const data = await res.json();

    if (!res.ok) {
      alert(data.error || 'Scan failed');
      setScanning(false);
      return;
    }

    currentScanId = data.scanId;
    progressPorts.textContent = `0 / ${data.totalPorts} ports`;
    listenToScan(data.scanId, data.totalPorts);
  } catch (err) {
    alert('Failed to start scan: ' + err.message);
    setScanning(false);
  }
}

function listenToScan(scanId, totalPorts) {
  const evtSource = new EventSource(`/api/scan/${scanId}/stream`);

  evtSource.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === 'progress') {
      progressFill.style.width = data.percent + '%';
      progressText.textContent = data.percent + '%';
      progressPorts.textContent = `${data.completed} / ${totalPorts} ports`;

      if (data.lastResult && data.lastResult.state === 'open') {
        addFeedItem(data.lastResult);
      }
    }

    if (data.type === 'complete') {
      evtSource.close();
      progressFill.style.width = '100%';
      progressText.textContent = '100%';
      setScanning(false);
      displayResults(data.results);
      autoSave(scanId);
    }

    if (data.type === 'error') {
      evtSource.close();
      setScanning(false);
      alert('Scan error: ' + data.error);
    }
  };

  evtSource.onerror = () => {
    evtSource.close();
    setTimeout(() => pollResults(scanId), 2000);
  };
}

async function pollResults(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}`);
    const data = await res.json();

    if (data.status === 'completed' && data.results) {
      setScanning(false);
      displayResults(data.results);
      autoSave(scanId);
    } else if (data.status === 'running') {
      setTimeout(() => pollResults(scanId), 2000);
    } else if (data.status === 'error') {
      setScanning(false);
      alert('Scan error: ' + (data.error || 'Unknown error'));
    }
  } catch {
    setScanning(false);
  }
}

async function autoSave(scanId) {
  try {
    await fetch(`/api/scan/${scanId}/save`, { method: 'POST' });
    loadHistory();
  } catch {
  }
}

function displayResults(results) {
  resultsSection.style.display = 'block';
  resultsSection.classList.add('animate-in');

  const security = results.security || {};
  const grade = security.grade || {};
  const detectedOS = security.detectedOS || null;
  const securityScore = security.securityScore != null ? security.securityScore : null;

  summaryGrid.innerHTML = `
    <div class="summary-item host">
      <div class="value">${esc(results.ip)}</div>
      <div class="label">${esc(results.host)}</div>
    </div>
    <div class="summary-item open">
      <div class="value">${results.summary.open}</div>
      <div class="label">Open Ports</div>
    </div>
    <div class="summary-item closed">
      <div class="value">${results.summary.closed}</div>
      <div class="label">Closed</div>
    </div>
    <div class="summary-item filtered">
      <div class="value">${results.summary.filtered}</div>
      <div class="label">Filtered</div>
    </div>
    <div class="summary-item time">
      <div class="value">${esc(results.duration)}</div>
      <div class="label">Duration</div>
    </div>
    ${detectedOS && detectedOS !== 'Unknown' ? `
    <div class="summary-item os-item">
      <div class="value">${esc(detectedOS)}</div>
      <div class="label">Detected OS</div>
    </div>` : ''}
  `;

  if (securityScore != null && grade.grade) {
    const color = grade.color || '#94a3b8';
    const dashLen = (securityScore / 100) * 326.73;
    securityScoreSection.style.display = 'block';
    securityScoreSection.innerHTML = `
      <div class="score-wrapper">
        <div class="score-circle">
          <svg viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8"/>
            <circle cx="60" cy="60" r="52" fill="none" stroke="${color}" stroke-width="8"
              stroke-dasharray="${dashLen} 326.73" stroke-linecap="round" transform="rotate(-90 60 60)"/>
          </svg>
          <div class="score-inner">
            <span class="score-grade" style="color:${color}">${grade.grade}</span>
            <span class="score-number">${securityScore}/100</span>
          </div>
        </div>
        <div class="score-info">
          <div class="score-label" style="color:${color}">${esc(grade.label || 'Unknown')}</div>
          <div class="score-subtitle">Security Score</div>
          <div class="vuln-badges">
            ${security.criticalCount ? `<span class="vbadge vbadge-critical">${security.criticalCount} Critical</span>` : ''}
            ${security.highCount ? `<span class="vbadge vbadge-high">${security.highCount} High</span>` : ''}
            ${security.mediumCount ? `<span class="vbadge vbadge-medium">${security.mediumCount} Medium</span>` : ''}
            ${security.lowCount ? `<span class="vbadge vbadge-low">${security.lowCount} Low</span>` : ''}
          </div>
        </div>
      </div>
    `;
  } else {
    securityScoreSection.style.display = 'none';
    securityScoreSection.innerHTML = '';
  }

  resultsBody.innerHTML = '';
  if (results.openPorts.length === 0) {
    resultsBody.innerHTML = '<tr><td colspan="5" class="empty-state">No open ports found</td></tr>';
  } else {
    for (const port of results.openPorts) {
      const risk = port.risk || { level: 'info' };
      const banner = port.serviceInfo?.banner || port.banner || '-';
      const details = port.serviceInfo?.details || {};
      let detailText = banner;
      if (details.server) detailText = 'Server: ' + details.server;
      if (details.software) detailText = 'Software: ' + details.software;
      if (details.authRequired !== undefined) detailText = details.authRequired ? 'Auth Required' : 'No Auth!';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${port.port}</strong></td>
        <td><span class="badge badge-${port.state}">${port.state}</span></td>
        <td>${esc(port.service)}</td>
        <td><span class="risk-${risk.level}">${risk.level.toUpperCase()}</span></td>
        <td><span class="banner-text" title="${esc(banner)}">${esc(detailText)}</span></td>
      `;
      resultsBody.appendChild(tr);
    }
  }

  const vulnerabilities = security.vulnerabilities || [];
  if (vulnerabilities.length > 0) {
    vulnSection.style.display = 'block';
    let rows = '';
    for (const v of vulnerabilities) {
      const sev = (v.severity || 'medium').toLowerCase();
      rows += `
        <tr>
          <td><strong>${v.port || '-'}</strong></td>
          <td>${esc(v.service || '-')}</td>
          <td><span class="sev-badge sev-${sev}">${(v.severity || 'UNKNOWN').toUpperCase()}</span></td>
          <td><code class="cve-code">${esc(v.cve || 'N/A')}</code></td>
          <td class="vuln-desc">${esc(v.description || '-')}</td>
        </tr>
      `;
    }
    vulnSection.innerHTML = `
      <h3 class="section-title">Vulnerabilities Found (${vulnerabilities.length})</h3>
      <div class="table-container">
        <table class="results-table">
          <thead>
            <tr><th>Port</th><th>Service</th><th>Severity</th><th>CVE</th><th>Description</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;
  } else {
    vulnSection.style.display = 'none';
    vulnSection.innerHTML = '';
  }

  if (results.recommendations && results.recommendations.length > 0) {
    let html = '<h3 class="section-title">Security Recommendations</h3>';
    for (const rec of results.recommendations) {
      const cls = rec.severity.toLowerCase();
      html += `
        <div class="rec-item rec-${cls}">
          <span class="rec-severity">[${rec.severity}]</span>
          ${esc(rec.recommendation)}
        </div>
      `;
    }
    recommendationsDiv.innerHTML = html;
  } else {
    recommendationsDiv.innerHTML = '<p class="empty-state">No security concerns detected</p>';
  }

  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function exportResults(format) {
  if (!currentScanId) return;
  window.open(`/api/scan/${currentScanId}/export/${format}`, '_blank');
}

async function discoverNetwork() {
  btnNetDiscover.disabled = true;
  btnNetDiscover.textContent = 'Discovering...';
  netDiscoverResults.innerHTML = '<p class="empty-state">Scanning local network...</p>';

  try {
    const ifaceRes = await fetch('/api/network/local');
    const ifaces = await ifaceRes.json();

    if (!ifaceRes.ok || !Array.isArray(ifaces) || ifaces.length === 0) {
      netDiscoverResults.innerHTML = '<p class="empty-state">No network interfaces found</p>';
      resetDiscoverBtn();
      return;
    }

    let subnet = null;
    let cidr = 24;

    for (const iface of ifaces) {
      if (iface.ip) {
        const parts = iface.ip.split('.');
        parts[3] = '0';
        subnet = parts.join('.');
        if (iface.cidr) {
          const cidrParts = iface.cidr.split('/');
          if (cidrParts.length === 2) cidr = parseInt(cidrParts[1]) || 24;
        }
        break;
      }
    }

    if (!subnet) {
      netDiscoverResults.innerHTML = '<p class="empty-state">Could not determine local subnet</p>';
      resetDiscoverBtn();
      return;
    }

    const discoverRes = await fetch('/api/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subnet, cidr })
    });

    const data = await discoverRes.json();

    if (!discoverRes.ok) {
      netDiscoverResults.innerHTML = `<p class="empty-state">${esc(data.error || 'Discovery failed')}</p>`;
      resetDiscoverBtn();
      return;
    }

    const hosts = data.hosts || [];

    if (hosts.length === 0) {
      netDiscoverResults.innerHTML = '<p class="empty-state">No active hosts found on the network</p>';
    } else {
      let html = `<div class="net-header">${hosts.length} host(s) found on ${esc(subnet)}/${cidr}</div>`;
      html += '<div class="net-list">';
      for (const host of hosts) {
        const ip = host.ip || '';
        const hostname = host.hostname || '';
        html += `
          <div class="net-item">
            <span class="net-ip">${esc(ip)}</span>
            ${hostname ? `<span class="net-hostname">${esc(hostname)}</span>` : ''}
            <button class="btn-export btn-scan-host" onclick="scanHost('${esc(ip)}')">Scan</button>
          </div>
        `;
      }
      html += '</div>';
      netDiscoverResults.innerHTML = html;
    }
  } catch (err) {
    netDiscoverResults.innerHTML = `<p class="empty-state">Error: ${esc(err.message)}</p>`;
  }

  resetDiscoverBtn();
}

function resetDiscoverBtn() {
  btnNetDiscover.disabled = false;
  btnNetDiscover.textContent = 'Discover Hosts';
}

function scanHost(ip) {
  if (!ip) return;
  targetInput.value = ip;
  targetInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
  targetInput.focus();
}

async function loadHistory() {
  try {
    const res = await fetch('/api/results');
    const results = await res.json();

    if (results.length === 0) {
      historyList.innerHTML = '<p class="empty-state">No saved scans yet</p>';
      return;
    }

    historyList.innerHTML = results.map((r) => `
      <div class="history-item">
        <div class="history-info">
          <span class="history-host">${esc(r.host)}</span>
          <span class="history-date">${new Date(r.date).toLocaleString()}</span>
        </div>
        <div class="history-meta">
          <span class="history-ports">${r.openPorts} open ports</span>
          ${r.score != null ? `<span class="history-score">Score: ${r.score}</span>` : ''}
        </div>
      </div>
    `).join('');
  } catch {
  }
}

function setScanning(scanning) {
  btnScan.disabled = scanning;
  btnScan.querySelector('.btn-text').style.display = scanning ? 'none' : 'inline';
  btnScan.querySelector('.btn-loading').style.display = scanning ? 'inline' : 'none';
  if (scanning) btnScan.classList.add('scanning');
  else btnScan.classList.remove('scanning');
}

function addFeedItem(result) {
  const div = document.createElement('div');
  div.className = 'feed-open';
  div.textContent = `[OPEN] Port ${result.port} - ${result.service}`;
  liveFeed.insertBefore(div, liveFeed.firstChild);
  while (liveFeed.children.length > 50) {
    liveFeed.removeChild(liveFeed.lastChild);
  }
}

function esc(str) {
  if (!str) return '';
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}

loadHistory();
