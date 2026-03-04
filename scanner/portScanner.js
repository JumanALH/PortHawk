const net = require('net');
const dns = require('dns');
const { EventEmitter } = require('events');

const COMMON_PORTS = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 111: 'RPCBind', 135: 'MSRPC', 139: 'NetBIOS',
  143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP (Submission)',
  993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle DB',
  3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
  6379: 'Redis', 8080: 'HTTP Proxy', 8443: 'HTTPS Alt', 27017: 'MongoDB',
  9200: 'Elasticsearch', 11211: 'Memcached'
};

const TTL_OS_MAP = [
  { min: 0, max: 64, os: 'Linux/Unix/macOS' },
  { min: 65, max: 128, os: 'Windows' },
  { min: 129, max: 255, os: 'Network Device (Router/Switch)' }
];

class PortScanner extends EventEmitter {
  constructor(options = {}) {
    super();
    this.timeout = options.timeout || 2000;
    this.concurrency = options.concurrency || 100;
    this.retries = options.retries || 1;
  }

  async resolveHost(host) {
    return new Promise((resolve, reject) => {
      if (net.isIP(host)) {
        resolve(host);
        return;
      }
      dns.lookup(host, { family: 4 }, (err, address) => {
        if (!err && address) {
          resolve(address);
          return;
        }
        dns.resolve4(host, (err2, addresses) => {
          if (err2) reject(new Error(`Cannot resolve hostname: ${host}`));
          else resolve(addresses[0]);
        });
      });
    });
  }

  scanPort(host, port) {
    return new Promise((resolve) => {
      let retryCount = 0;

      const attempt = () => {
        const socket = new net.Socket();
        let resolved = false;

        const cleanup = (result) => {
          if (resolved) return;
          resolved = true;
          socket.removeAllListeners();
          socket.destroy();
          resolve(result);
        };

        socket.setTimeout(this.timeout);

        socket.on('connect', () => {
          let banner = '';
          socket.on('data', (data) => {
            banner += data.toString().trim();
          });

          setTimeout(() => {
            cleanup({
              port,
              state: 'open',
              service: COMMON_PORTS[port] || 'Unknown',
              banner: banner || null
            });
          }, 500);
        });

        socket.on('timeout', () => {
          if (retryCount < this.retries) {
            retryCount++;
            socket.destroy();
            resolved = false;
            attempt();
          } else {
            cleanup({
              port,
              state: 'filtered',
              service: COMMON_PORTS[port] || 'Unknown',
              banner: null
            });
          }
        });

        socket.on('error', (err) => {
          if (err.code === 'ECONNREFUSED') {
            cleanup({
              port,
              state: 'closed',
              service: COMMON_PORTS[port] || 'Unknown',
              banner: null
            });
          } else if (retryCount < this.retries) {
            retryCount++;
            socket.destroy();
            resolved = false;
            attempt();
          } else {
            cleanup({
              port,
              state: 'filtered',
              service: COMMON_PORTS[port] || 'Unknown',
              banner: null
            });
          }
        });

        socket.connect(port, host);
      };

      attempt();
    });
  }

  async scan(host, ports) {
    const startTime = Date.now();
    const results = [];
    let completed = 0;
    const total = ports.length;

    let ip;
    try {
      ip = await this.resolveHost(host);
    } catch (err) {
      throw err;
    }

    this.emit('start', { host, ip, totalPorts: total });

    for (let i = 0; i < ports.length; i += this.concurrency) {
      const batch = ports.slice(i, i + this.concurrency);
      const batchResults = await Promise.all(
        batch.map((port) => this.scanPort(ip, port))
      );

      for (const result of batchResults) {
        results.push(result);
        completed++;
        this.emit('progress', {
          completed,
          total,
          percent: Math.round((completed / total) * 100),
          lastResult: result
        });
      }
    }

    const endTime = Date.now();
    const duration = (endTime - startTime) / 1000;

    const openPorts = results.filter((r) => r.state === 'open');
    const closedPorts = results.filter((r) => r.state === 'closed');
    const filteredPorts = results.filter((r) => r.state === 'filtered');

    const scanResult = {
      host,
      ip,
      scanDate: new Date().toISOString(),
      duration: `${duration.toFixed(2)}s`,
      totalScanned: total,
      summary: {
        open: openPorts.length,
        closed: closedPorts.length,
        filtered: filteredPorts.length
      },
      openPorts,
      allResults: results
    };

    this.emit('complete', scanResult);
    return scanResult;
  }

  static parsePorts(portString) {
    const ports = new Set();

    const parts = portString.split(',').map((s) => s.trim());
    for (const part of parts) {
      if (part.includes('-')) {
        const [start, end] = part.split('-').map(Number);
        if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
          throw new Error(`Invalid port range: ${part}`);
        }
        for (let i = start; i <= end; i++) {
          ports.add(i);
        }
      } else {
        const port = Number(part);
        if (isNaN(port) || port < 1 || port > 65535) {
          throw new Error(`Invalid port: ${part}`);
        }
        ports.add(port);
      }
    }

    return Array.from(ports).sort((a, b) => a - b);
  }

  static getPresetPorts(preset) {
    switch (preset) {
      case 'top100':
        return [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106,
          110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
          443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
          631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
          1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
          2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
          5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
          6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
          9100, 9999, 10000, 27017, 32768, 49152, 49153, 49154, 49155];
      case 'common':
        return Object.keys(COMMON_PORTS).map(Number);
      case 'quick':
        return [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080];
      default:
        return PortScanner.parsePorts('1-1024');
    }
  }
}

module.exports = { PortScanner, COMMON_PORTS, TTL_OS_MAP };
