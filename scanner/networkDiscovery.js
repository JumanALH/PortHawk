const net = require('net');
const dns = require('dns');
const dgram = require('dgram');
const os = require('os');

class NetworkDiscovery {
  constructor(timeout = 1500) {
    this.timeout = timeout;
  }

  getLocalNetworkInfo() {
    const interfaces = os.networkInterfaces();
    const results = [];

    // Patterns for virtual/non-physical adapters to skip
    const virtualPatterns = /virtual|vbox|vmware|vmnet|docker|veth|tap|tun|bridge|hyper-v|pseudo|loopback/i;

    // First pass: only real physical interfaces
    for (const [name, addrs] of Object.entries(interfaces)) {
      if (virtualPatterns.test(name)) continue;

      for (const addr of addrs) {
        if (addr.family === 'IPv4' && !addr.internal) {
          // Skip 192.168.56.x range (VirtualBox host-only default range)
          if (addr.address.startsWith('192.168.56.')) continue;

          results.push({
            interface: name,
            ip: addr.address,
            netmask: addr.netmask,
            mac: addr.mac,
            cidr: addr.cidr || `${addr.address}/${this._netmaskToCidr(addr.netmask)}`
          });
        }
      }
    }

    // Fallback: if no real interfaces found, return all non-internal IPv4
    if (results.length === 0) {
      for (const [name, addrs] of Object.entries(interfaces)) {
        for (const addr of addrs) {
          if (addr.family === 'IPv4' && !addr.internal) {
            results.push({
              interface: name,
              ip: addr.address,
              netmask: addr.netmask,
              mac: addr.mac,
              cidr: addr.cidr || `${addr.address}/${this._netmaskToCidr(addr.netmask)}`
            });
          }
        }
      }
    }

    return results;
  }

  _netmaskToCidr(netmask) {
    return netmask.split('.').reduce((acc, octet) => {
      return acc + (parseInt(octet) >>> 0).toString(2).split('1').length - 1;
    }, 0);
  }

  generateSubnetIPs(baseIP, cidr) {
    const ips = [];
    const parts = baseIP.split('.').map(Number);
    const hostBits = 32 - cidr;
    const totalHosts = Math.pow(2, hostBits);

    const networkAddr =
      ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    const mask = (~0 << hostBits) >>> 0;
    const network = (networkAddr & mask) >>> 0;

    const maxHosts = Math.min(totalHosts - 2, 254);

    for (let i = 1; i <= maxHosts; i++) {
      const ip = network + i;
      ips.push(
        `${(ip >>> 24) & 255}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}`
      );
    }

    return ips;
  }

  pingHost(host) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      const startTime = Date.now();

      socket.setTimeout(this.timeout);

      socket.on('connect', () => {
        const latency = Date.now() - startTime;
        socket.destroy();
        resolve({ alive: true, latency, method: 'tcp-80' });
      });

      socket.on('error', (err) => {
        socket.destroy();
        if (err.code === 'ECONNREFUSED') {
          const latency = Date.now() - startTime;
          resolve({ alive: true, latency, method: 'tcp-rst' });
        } else {
          resolve({ alive: false, latency: null, method: null });
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ alive: false, latency: null, method: null });
      });

      socket.connect(80, host);
    });
  }

  async multiPortPing(host) {
    const ports = [80, 443, 22, 445, 3389];

    for (const port of ports) {
      const result = await new Promise((resolve) => {
        const socket = new net.Socket();
        const startTime = Date.now();

        socket.setTimeout(this.timeout);

        socket.on('connect', () => {
          const latency = Date.now() - startTime;
          socket.destroy();
          resolve({ alive: true, latency, method: `tcp-${port}` });
        });

        socket.on('error', (err) => {
          socket.destroy();
          if (err.code === 'ECONNREFUSED') {
            const latency = Date.now() - startTime;
            resolve({ alive: true, latency, method: `tcp-${port}-rst` });
          } else {
            resolve({ alive: false });
          }
        });

        socket.on('timeout', () => {
          socket.destroy();
          resolve({ alive: false });
        });

        socket.connect(port, host);
      });

      if (result.alive) return result;
    }

    return { alive: false, latency: null, method: null };
  }

  async discoverHosts(baseIP, cidr, concurrency = 30) {
    const ips = this.generateSubnetIPs(baseIP, cidr);
    const alive = [];
    let scanned = 0;

    for (let i = 0; i < ips.length; i += concurrency) {
      const batch = ips.slice(i, i + concurrency);
      const results = await Promise.all(
        batch.map(async (ip) => {
          const ping = await this.multiPortPing(ip);
          scanned++;

          let hostname = null;
          if (ping.alive) {
            try {
              const names = await new Promise((resolve, reject) => {
                dns.reverse(ip, (err, hostnames) => {
                  if (err) reject(err);
                  else resolve(hostnames);
                });
              });
              hostname = names[0] || null;
            } catch {
            }
          }

          return {
            ip,
            ...ping,
            hostname,
            scanned,
            total: ips.length
          };
        })
      );

      for (const r of results) {
        if (r.alive) alive.push(r);
      }
    }

    return {
      subnet: `${baseIP}/${cidr}`,
      totalScanned: ips.length,
      aliveHosts: alive.length,
      hosts: alive
    };
  }

  async reverseLookup(ip) {
    return new Promise((resolve) => {
      dns.reverse(ip, (err, hostnames) => {
        if (err) resolve(null);
        else resolve(hostnames[0] || null);
      });
    });
  }

  async getWhoisInfo(host) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let data = '';

      socket.setTimeout(5000);

      socket.on('connect', () => {
        socket.write(`${host}\r\n`);
      });

      socket.on('data', (chunk) => {
        data += chunk.toString();
      });

      socket.on('close', () => {
        const info = {};
        const lines = data.split('\n');
        for (const line of lines) {
          const match = line.match(/^([^:]+):\s*(.+)/);
          if (match) {
            const key = match[1].trim().toLowerCase();
            if (['orgname', 'org-name', 'organization', 'country', 'netname', 'descr', 'abuse-mailbox'].includes(key)) {
              info[key] = match[2].trim();
            }
          }
        }
        resolve(Object.keys(info).length > 0 ? info : null);
      });

      socket.on('error', () => {
        socket.destroy();
        resolve(null);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(null);
      });

      socket.connect(43, 'whois.arin.net');
    });
  }
}

module.exports = { NetworkDiscovery };
