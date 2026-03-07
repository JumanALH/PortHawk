const express = require('express');
const path = require('path');
const fs = require('fs');
const { PortScanner } = require('./scanner/portScanner');
const { ServiceDetector } = require('./scanner/serviceDetector');
const { VulnChecker } = require('./scanner/vulnChecker');
const { NetworkDiscovery } = require('./scanner/networkDiscovery');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const activeScans = new Map();

function validateTarget(target) {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

  if (!ipRegex.test(target) && !hostnameRegex.test(target)) {
    return false;
  }

  if (ipRegex.test(target)) {
    const parts = target.split('.').map(Number);
    if (parts.some((p) => p > 255)) return false;
  }

  return true;
}

app.post('/api/scan', async (req, res) => {
  const { target, portRange, preset, timeout, concurrency } = req.body;

  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  if (!validateTarget(target)) {
    return res.status(400).json({ error: 'Invalid target. Use a valid IP or hostname.' });
  }

  let ports;
  try {
    if (preset) {
      ports = PortScanner.getPresetPorts(preset);
    } else if (portRange) {
      ports = PortScanner.parsePorts(portRange);
    } else {
      ports = PortScanner.getPresetPorts('common');
    }
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  if (ports.length > 10000) {
    return res.status(400).json({ error: 'Maximum 10,000 ports per scan' });
  }

  const scanId = Date.now().toString(36) + Math.random().toString(36).substring(2, 6);

  const scanner = new PortScanner({
    timeout: Math.min(timeout || 2000, 10000),
    concurrency: Math.min(concurrency || 100, 200)
  });

  const scanState = {
    id: scanId,
    status: 'running',
    target,
    progress: 0,
    results: null,
    listeners: []
  };

  activeScans.set(scanId, scanState);

  scanner.on('progress', (data) => {
    scanState.progress = data.percent;
    for (const listener of scanState.listeners) {
      listener.write(`data: ${JSON.stringify({ type: 'progress', ...data })}\n\n`);
    }
  });

  res.json({ scanId, totalPorts: ports.length });

  try {
    const results = await scanner.scan(target, ports);

    const detector = new ServiceDetector();
    const enhancedPorts = [];

    for (const port of results.openPorts) {
      const serviceInfo = await detector.detect(results.ip, port.port);
      const risk = ServiceDetector.getRisk(port.port);
      enhancedPorts.push({
        ...port,
        serviceInfo: serviceInfo || null,
        risk
      });
    }

    results.openPorts = enhancedPorts;
    results.recommendations = ServiceDetector.getRecommendations(enhancedPorts);

    const vulnReport = VulnChecker.generateReport(results);
    results.security = vulnReport;

    scanState.status = 'completed';
    scanState.results = results;

    for (const listener of scanState.listeners) {
      listener.write(`data: ${JSON.stringify({ type: 'complete', results })}\n\n`);
      listener.end();
    }
  } catch (err) {
    scanState.status = 'error';
    scanState.error = err.message;

    for (const listener of scanState.listeners) {
      listener.write(`data: ${JSON.stringify({ type: 'error', error: err.message })}\n\n`);
      listener.end();
    }
  }

  setTimeout(() => activeScans.delete(scanId), 600000);
});

app.get('/api/scan/:id/stream', (req, res) => {
  const scan = activeScans.get(req.params.id);

  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });

  if (scan.status === 'completed') {
    res.write(`data: ${JSON.stringify({ type: 'complete', results: scan.results })}\n\n`);
    res.end();
    return;
  }

  if (scan.status === 'error') {
    res.write(`data: ${JSON.stringify({ type: 'error', error: scan.error })}\n\n`);
    res.end();
    return;
  }

  scan.listeners.push(res);

  req.on('close', () => {
    scan.listeners = scan.listeners.filter((l) => l !== res);
  });
});

app.get('/api/scan/:id', (req, res) => {
  const scan = activeScans.get(req.params.id);

  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  res.json({
    id: scan.id,
    status: scan.status,
    progress: scan.progress,
    results: scan.results,
    error: scan.error || null
  });
});

app.post('/api/discover', async (req, res) => {
  let { subnet, cidr } = req.body;

  if (!subnet || !cidr) {
    const discovery = new NetworkDiscovery();
    const interfaces = discovery.getLocalNetworkInfo();
    
    if (!interfaces || interfaces.length === 0) {
      return res.status(400).json({ error: 'Subnet and CIDR required' });
    }

    const iface = interfaces[0];
    const cidrFull = iface.cidr; 
    subnet = cidrFull.split('/')[0];
    cidr = parseInt(cidrFull.split('/')[1]);
  }

  cidr = parseInt(cidr);

  // اذا CIDR خارج النطاق، استخدم /24 تلقائياً
  if (cidr < 24 || cidr > 30) {
    cidr = 24;
  }
  try {
    const discovery = new NetworkDiscovery();
    const results = await discovery.discoverHosts(subnet, cidr);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/network/local', (req, res) => {
  const discovery = new NetworkDiscovery();
  const info = discovery.getLocalNetworkInfo();
  res.json(info);
});

app.get('/api/scan/:id/export/:format', (req, res) => {
  const scan = activeScans.get(req.params.id);

  if (!scan || !scan.results) {
    return res.status(404).json({ error: 'Scan results not found' });
  }

  const { format } = req.params;

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=porthawk-${scan.id}.json`);
    res.json(scan.results);
  } else if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=porthawk-${scan.id}.csv`);

    let csv = 'Port,State,Service,Risk Level,Banner\n';
    for (const port of scan.results.openPorts) {
      const banner = (port.banner || '').replace(/"/g, '""');
      csv += `${port.port},${port.state},${port.service},${port.risk?.level || 'N/A'},"${banner}"\n`;
    }
    res.send(csv);
  } else if (format === 'html') {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', `attachment; filename=porthawk-${scan.id}.html`);
    res.send(generateHTMLReport(scan.results));
  } else {
    res.status(400).json({ error: 'Unsupported format. Use json, csv, or html.' });
  }
});

function generateHTMLReport(results) {
  const security = results.security || {};
  const grade = security.grade || { grade: '?', label: 'Unknown', color: '#666' };

  let portsRows = '';
  for (const port of results.openPorts) {
    const risk = port.risk || { level: 'info' };
    const banner = port.serviceInfo?.banner || port.banner || '-';
    portsRows += `<tr>
      <td>${port.port}</td>
      <td><span class="badge-open">OPEN</span></td>
      <td>${port.service}</td>
      <td><span class="risk-${risk.level}">${risk.level.toUpperCase()}</span></td>
      <td>${banner.substring(0, 80)}</td>
    </tr>`;
  }

  let vulnRows = '';
  if (security.vulnerabilities) {
    for (const v of security.vulnerabilities) {
      vulnRows += `<tr>
        <td>${v.port}</td>
        <td>${v.service}</td>
        <td><span class="sev-${v.severity.toLowerCase()}">${v.severity}</span></td>
        <td>${v.cve}</td>
        <td>${v.description}</td>
      </tr>`;
    }
  }

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PortHawk Report - ${results.host}</title>
<style>
body{font-family:Arial,sans-serif;background:#0a0e17;color:#e2e8f0;padding:40px;max-width:1000px;margin:0 auto}
h1{color:#00d4ff;border-bottom:2px solid #2a3a50;padding-bottom:10px}
h2{color:#a855f7;margin-top:30px}
.meta{background:#1a2332;padding:20px;border-radius:8px;margin:20px 0}
.meta span{margin-right:30px}
.score{display:inline-block;width:80px;height:80px;border-radius:50%;text-align:center;line-height:80px;font-size:2rem;font-weight:bold;color:white;background:${grade.color}}
table{width:100%;border-collapse:collapse;margin:15px 0}
th{background:#1a2332;padding:10px;text-align:left;color:#94a3b8;font-size:0.85rem}
td{padding:10px;border-bottom:1px solid #2a3a50;font-size:0.9rem}
.badge-open{background:rgba(34,197,94,0.2);color:#22c55e;padding:2px 8px;border-radius:10px;font-size:0.8rem}
.risk-critical,.sev-critical{color:#ef4444;font-weight:bold}
.risk-high,.sev-high{color:#f97316;font-weight:bold}
.risk-medium,.sev-medium{color:#f59e0b}
.risk-low,.sev-low{color:#22c55e}
.risk-info{color:#94a3b8}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #2a3a50;color:#64748b;font-size:0.8rem}
</style></head><body>
<h1>PortHawk - Security Scan Report</h1>
<div class="meta">
<strong>Target:</strong> <span>${results.host} (${results.ip})</span>
<strong>Date:</strong> <span>${results.scanDate}</span>
<strong>Duration:</strong> <span>${results.duration}</span>
<strong>OS:</strong> <span>${security.detectedOS || 'Unknown'}</span>
</div>
<h2>Security Score</h2>
<div class="meta">
<span class="score">${grade.grade}</span>
<span style="margin-left:20px;font-size:1.2rem">${security.securityScore}/100 - ${grade.label}</span>
<br><br>
<span>Open: ${results.summary.open}</span>
<span>Closed: ${results.summary.closed}</span>
<span>Filtered: ${results.summary.filtered}</span>
<span>Vulnerabilities: ${security.totalVulns || 0}</span>
</div>
<h2>Open Ports (${results.openPorts.length})</h2>
<table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Risk</th><th>Banner</th></tr></thead>
<tbody>${portsRows || '<tr><td colspan="5">No open ports found</td></tr>'}</tbody></table>
${vulnRows ? `<h2>Vulnerabilities (${security.totalVulns})</h2>
<table><thead><tr><th>Port</th><th>Service</th><th>Severity</th><th>CVE</th><th>Description</th></tr></thead>
<tbody>${vulnRows}</tbody></table>` : ''}
<div class="footer">Generated by PortHawk                          | For authorized security testing only</div>
</body></html>`;
}

app.post('/api/scan/:id/save', (req, res) => {
  const scan = activeScans.get(req.params.id);

  if (!scan || !scan.results) {
    return res.status(404).json({ error: 'Scan results not found' });
  }

  const resultsDir = path.join(__dirname, 'results');
  if (!fs.existsSync(resultsDir)) {
    fs.mkdirSync(resultsDir, { recursive: true });
  }

  const filename = `porthawk-${scan.results.host}-${scan.id}.json`;
  const filepath = path.join(resultsDir, filename);

  fs.writeFileSync(filepath, JSON.stringify(scan.results, null, 2));

  res.json({ message: 'Results saved', filename, path: filepath });
});

app.get('/api/results', (req, res) => {
  const resultsDir = path.join(__dirname, 'results');

  if (!fs.existsSync(resultsDir)) {
    return res.json([]);
  }

  const files = fs.readdirSync(resultsDir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => {
      const content = JSON.parse(fs.readFileSync(path.join(resultsDir, f), 'utf8'));
      return {
        filename: f,
        host: content.host,
        date: content.scanDate,
        openPorts: content.summary?.open || 0,
        score: content.security?.securityScore || null
      };
    });

  res.json(files);
});

app.listen(PORT, () => {
  console.log(`\n  +----------------------------------------+`);
  console.log(`  |   🦅 PortHawk                          |`);
  console.log(`  |   http://localhost:${PORT}                 |`);
  console.log(`  |   Press Ctrl+C to stop                 |`);
  console.log(`  +----------------------------------------+\n`);
});
