const net = require('net');

const SERVICE_PROBES = [
  {
    name: 'HTTP',
    ports: [80, 8080, 8000, 8888, 3000, 5000],
    probe: 'GET / HTTP/1.1\r\nHost: target\r\n\r\n',
    match: /HTTP\/[\d.]+\s+\d+/i,
    extract: (data) => {
      const server = data.match(/Server:\s*(.+)/i);
      const powered = data.match(/X-Powered-By:\s*(.+)/i);
      return {
        server: server ? server[1].trim() : null,
        poweredBy: powered ? powered[1].trim() : null
      };
    }
  },
  {
    name: 'HTTPS',
    ports: [443, 8443],
    probe: null,
    match: null,
    extract: () => ({ note: 'TLS/SSL encrypted service' })
  },
  {
    name: 'SSH',
    ports: [22],
    probe: null,
    match: /^SSH-/i,
    extract: (data) => {
      const version = data.match(/SSH-([\d.]+)-(.+)/);
      return {
        protocol: version ? version[1] : null,
        software: version ? version[2].trim() : null
      };
    }
  },
  {
    name: 'FTP',
    ports: [21],
    probe: null,
    match: /^220[\s-]/,
    extract: (data) => {
      const info = data.match(/^220[\s-](.+)/);
      return { banner: info ? info[1].trim() : null };
    }
  },
  {
    name: 'SMTP',
    ports: [25, 465, 587],
    probe: 'EHLO scanner\r\n',
    match: /^220[\s-]/,
    extract: (data) => {
      const info = data.match(/^220[\s-](.+)/m);
      return { banner: info ? info[1].trim() : null };
    }
  },
  {
    name: 'MySQL',
    ports: [3306],
    probe: null,
    match: /mysql|MariaDB/i,
    extract: (data) => {
      return { banner: data.replace(/[^\x20-\x7E]/g, '').substring(0, 100) };
    }
  },
  {
    name: 'Redis',
    ports: [6379],
    probe: 'PING\r\n',
    match: /\+PONG|-NOAUTH/,
    extract: (data) => {
      const authRequired = data.includes('-NOAUTH');
      return { authRequired, response: data.trim() };
    }
  },
  {
    name: 'MongoDB',
    ports: [27017],
    probe: null,
    match: /mongodb|ismaster|mongod/i,
    extract: (data) => {
      return { banner: data.replace(/[^\x20-\x7E]/g, '').substring(0, 100) };
    }
  }
];

const PORT_RISKS = {
  21: { level: 'high', reason: 'FTP - often unencrypted, credentials sent in plain text' },
  22: { level: 'medium', reason: 'SSH - secure but target for brute force attacks' },
  23: { level: 'critical', reason: 'Telnet - unencrypted, highly insecure' },
  25: { level: 'medium', reason: 'SMTP - can be used for email relay if misconfigured' },
  53: { level: 'medium', reason: 'DNS - potential for DNS amplification attacks' },
  80: { level: 'low', reason: 'HTTP - standard web traffic, check for HTTPS redirect' },
  110: { level: 'high', reason: 'POP3 - unencrypted email protocol' },
  135: { level: 'high', reason: 'MSRPC - commonly exploited on Windows' },
  139: { level: 'high', reason: 'NetBIOS - can expose sensitive information' },
  143: { level: 'high', reason: 'IMAP - unencrypted email protocol' },
  443: { level: 'low', reason: 'HTTPS - encrypted web traffic' },
  445: { level: 'critical', reason: 'SMB - frequent target for ransomware and exploits' },
  1433: { level: 'critical', reason: 'MSSQL - database exposed to network' },
  3306: { level: 'critical', reason: 'MySQL - database exposed to network' },
  3389: { level: 'high', reason: 'RDP - remote desktop, brute force target' },
  5432: { level: 'critical', reason: 'PostgreSQL - database exposed to network' },
  5900: { level: 'high', reason: 'VNC - remote desktop, often weakly secured' },
  6379: { level: 'critical', reason: 'Redis - often no authentication by default' },
  8080: { level: 'medium', reason: 'HTTP Proxy - check for open proxy misconfiguration' },
  27017: { level: 'critical', reason: 'MongoDB - often no authentication by default' }
};

class ServiceDetector {
  constructor(timeout = 3000) {
    this.timeout = timeout;
  }

  async detect(host, port) {
    const probes = SERVICE_PROBES.filter(
      (p) => p.ports.includes(port) || !p.ports.length
    );

    for (const probe of probes) {
      try {
        const result = await this._probe(host, port, probe);
        if (result) return result;
      } catch {
      }
    }

    try {
      const banner = await this._grabBanner(host, port);
      if (banner) {
        for (const probe of SERVICE_PROBES) {
          if (probe.match && probe.match.test(banner)) {
            const details = probe.extract ? probe.extract(banner) : {};
            return {
              service: probe.name,
              details,
              banner: banner.substring(0, 200)
            };
          }
        }
        return {
          service: 'Unknown',
          details: {},
          banner: banner.substring(0, 200)
        };
      }
    } catch {
    }

    return null;
  }

  _probe(host, port, probeConfig) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let data = '';
      let resolved = false;

      socket.setTimeout(this.timeout);

      socket.on('connect', () => {
        if (probeConfig.probe) {
          const probeData = probeConfig.probe.replace('target', host);
          socket.write(probeData);
        }
      });

      socket.on('data', (chunk) => {
        data += chunk.toString('utf8');
        if (data.length > 1024) {
          finish();
        }
      });

      socket.on('timeout', finish);
      socket.on('error', () => {
        if (!resolved) {
          resolved = true;
          socket.destroy();
          reject(new Error('Connection failed'));
        }
      });

      function finish() {
        if (resolved) return;
        resolved = true;
        socket.destroy();

        if (data && probeConfig.match && probeConfig.match.test(data)) {
          const details = probeConfig.extract ? probeConfig.extract(data) : {};
          resolve({
            service: probeConfig.name,
            details,
            banner: data.substring(0, 200)
          });
        } else if (data && !probeConfig.match) {
          resolve({
            service: probeConfig.name,
            details: probeConfig.extract ? probeConfig.extract(data) : {},
            banner: data.substring(0, 200)
          });
        } else {
          resolve(null);
        }
      }

      setTimeout(finish, this.timeout - 100);
      socket.connect(port, host);
    });
  }

  _grabBanner(host, port) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let data = '';

      socket.setTimeout(this.timeout);

      socket.on('connect', () => {
        socket.write('\r\n');
      });

      socket.on('data', (chunk) => {
        data += chunk.toString('utf8');
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(data || null);
      });

      socket.on('error', () => {
        socket.destroy();
        reject(new Error('Banner grab failed'));
      });

      socket.on('close', () => {
        resolve(data || null);
      });

      socket.connect(port, host);
    });
  }

  static getRisk(port) {
    return PORT_RISKS[port] || { level: 'info', reason: 'No specific risk assessment available' };
  }

  static getRecommendations(openPorts) {
    const recommendations = [];

    for (const portInfo of openPorts) {
      const risk = ServiceDetector.getRisk(portInfo.port);

      if (risk.level === 'critical') {
        recommendations.push({
          port: portInfo.port,
          service: portInfo.service,
          severity: 'CRITICAL',
          recommendation: `Port ${portInfo.port} (${portInfo.service}) is critically exposed. ${risk.reason}. Consider closing this port or restricting access with a firewall.`
        });
      } else if (risk.level === 'high') {
        recommendations.push({
          port: portInfo.port,
          service: portInfo.service,
          severity: 'HIGH',
          recommendation: `Port ${portInfo.port} (${portInfo.service}) poses a high risk. ${risk.reason}. Use encrypted alternatives or restrict access.`
        });
      } else if (risk.level === 'medium') {
        recommendations.push({
          port: portInfo.port,
          service: portInfo.service,
          severity: 'MEDIUM',
          recommendation: `Port ${portInfo.port} (${portInfo.service}): ${risk.reason}. Monitor and ensure proper configuration.`
        });
      }
    }

    return recommendations;
  }
}

module.exports = { ServiceDetector, PORT_RISKS };
