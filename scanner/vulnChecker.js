const VULN_DATABASE = {
  'SSH': [
    { pattern: /OpenSSH[_ ]([1-6]\.|7\.[0-3])/i, cve: 'CVE-2016-0777', severity: 'HIGH', desc: 'OpenSSH < 7.4 - Information leak via roaming' },
    { pattern: /OpenSSH[_ ]([1-6]\.|7\.[0-6])/i, cve: 'CVE-2018-15473', severity: 'MEDIUM', desc: 'OpenSSH < 7.7 - Username enumeration' },
    { pattern: /OpenSSH[_ ](8\.[0-4]p|[1-7]\.)/i, cve: 'CVE-2021-41617', severity: 'HIGH', desc: 'OpenSSH < 8.5 - Privilege escalation via AuthorizedKeysCommand' },
    { pattern: /dropbear/i, cve: 'MISC', severity: 'LOW', desc: 'Dropbear SSH detected - ensure latest version' }
  ],
  'HTTP': [
    { pattern: /Apache\/(2\.2\.|1\.|2\.0)/i, cve: 'CVE-2021-44790', severity: 'CRITICAL', desc: 'Apache < 2.4 - Multiple known vulnerabilities' },
    { pattern: /Apache\/2\.4\.([0-9]|[1-3][0-9]|4[0-9])(\s|$)/i, cve: 'CVE-2021-44790', severity: 'HIGH', desc: 'Apache 2.4.x < 2.4.50 - Buffer overflow in mod_lua' },
    { pattern: /nginx\/(0\.|1\.[0-9]\.|1\.1[0-8]\.)/i, cve: 'CVE-2021-23017', severity: 'HIGH', desc: 'nginx < 1.19 - DNS resolver vulnerability' },
    { pattern: /Microsoft-IIS\/(5\.|6\.|7\.0)/i, cve: 'CVE-2017-7269', severity: 'CRITICAL', desc: 'IIS < 7.5 - Remote code execution' },
    { pattern: /PHP\/(5\.|7\.[0-3])/i, cve: 'CVE-2019-11043', severity: 'CRITICAL', desc: 'PHP < 7.4 - Remote code execution via FPM' },
    { pattern: /Express/i, cve: 'INFO', severity: 'LOW', desc: 'Express.js detected - ensure X-Powered-By header is disabled' }
  ],
  'FTP': [
    { pattern: /vsftpd 2\.3\.4/i, cve: 'CVE-2011-2523', severity: 'CRITICAL', desc: 'vsftpd 2.3.4 - Backdoor command execution' },
    { pattern: /ProFTPD 1\.3\.[0-5]/i, cve: 'CVE-2019-12815', severity: 'HIGH', desc: 'ProFTPD < 1.3.6 - Arbitrary file copy' },
    { pattern: /FileZilla Server/i, cve: 'INFO', severity: 'LOW', desc: 'FileZilla FTP detected - ensure TLS is enabled' },
    { pattern: /Pure-FTPd/i, cve: 'INFO', severity: 'LOW', desc: 'Pure-FTPd detected - verify configuration hardening' }
  ],
  'SMTP': [
    { pattern: /Postfix/i, cve: 'INFO', severity: 'LOW', desc: 'Postfix SMTP detected - verify relay restrictions' },
    { pattern: /Exim ([1-3]\.|4\.[0-8])/i, cve: 'CVE-2019-10149', severity: 'CRITICAL', desc: 'Exim < 4.87 - Remote command execution' },
    { pattern: /Microsoft ESMTP/i, cve: 'INFO', severity: 'MEDIUM', desc: 'Exchange SMTP detected - check for ProxyLogon patches' }
  ],
  'MySQL': [
    { pattern: /5\.[0-5]\./i, cve: 'CVE-2012-2122', severity: 'CRITICAL', desc: 'MySQL < 5.6 - Authentication bypass' },
    { pattern: /MariaDB/i, cve: 'INFO', severity: 'LOW', desc: 'MariaDB detected - ensure version is up to date' }
  ],
  'Redis': [
    { pattern: /NOAUTH/i, cve: 'MISC', severity: 'CRITICAL', desc: 'Redis requires authentication - good security practice' },
    { pattern: /PONG/i, cve: 'CVE-2022-0543', severity: 'CRITICAL', desc: 'Redis without authentication - RCE possible via Lua sandbox escape' }
  ],
  'Telnet': [
    { pattern: /./i, cve: 'MISC', severity: 'CRITICAL', desc: 'Telnet is inherently insecure - all data sent in plaintext. Replace with SSH immediately.' }
  ],
  'SMB': [
    { pattern: /./i, cve: 'CVE-2017-0144', severity: 'CRITICAL', desc: 'SMB exposed - verify EternalBlue (MS17-010) and SMBGhost patches' }
  ],
  'RDP': [
    { pattern: /./i, cve: 'CVE-2019-0708', severity: 'CRITICAL', desc: 'RDP exposed - verify BlueKeep patch and enable NLA' }
  ],
  'MongoDB': [
    { pattern: /./i, cve: 'MISC', severity: 'CRITICAL', desc: 'MongoDB exposed - often no authentication by default, risk of data theft' }
  ]
};

const OS_SIGNATURES = {
  'ssh': [
    { pattern: /Ubuntu/i, os: 'Ubuntu Linux' },
    { pattern: /Debian/i, os: 'Debian Linux' },
    { pattern: /FreeBSD/i, os: 'FreeBSD' },
    { pattern: /CentOS/i, os: 'CentOS Linux' },
    { pattern: /Red Hat/i, os: 'Red Hat Enterprise Linux' },
    { pattern: /Raspbian/i, os: 'Raspbian (Raspberry Pi)' }
  ],
  'http': [
    { pattern: /Microsoft-IIS/i, os: 'Windows Server' },
    { pattern: /Win32|Win64/i, os: 'Windows' },
    { pattern: /Ubuntu/i, os: 'Ubuntu Linux' },
    { pattern: /Debian/i, os: 'Debian Linux' },
    { pattern: /CentOS/i, os: 'CentOS Linux' },
    { pattern: /Red Hat/i, os: 'Red Hat Enterprise Linux' },
    { pattern: /Unix/i, os: 'Unix-based OS' }
  ],
  'smtp': [
    { pattern: /Microsoft/i, os: 'Windows Server (Exchange)' },
    { pattern: /Ubuntu/i, os: 'Ubuntu Linux' },
    { pattern: /Debian/i, os: 'Debian Linux' }
  ]
};

class VulnChecker {
  static checkService(serviceName, banner) {
    if (!banner || !serviceName) return [];

    const vulns = [];
    const serviceVulns = VULN_DATABASE[serviceName] || [];

    for (const vuln of serviceVulns) {
      if (vuln.pattern.test(banner)) {
        vulns.push({
          cve: vuln.cve,
          severity: vuln.severity,
          description: vuln.desc
        });
      }
    }

    return vulns;
  }

  static detectOS(serviceName, banner) {
    if (!banner) return null;

    const key = serviceName.toLowerCase();
    const signatures = OS_SIGNATURES[key] || [];

    for (const sig of signatures) {
      if (sig.pattern.test(banner)) {
        return sig.os;
      }
    }

    return null;
  }

  static detectOSFromTTL(ttl) {
    if (ttl <= 64) return { os: 'Linux/Unix/macOS', confidence: 'medium' };
    if (ttl <= 128) return { os: 'Windows', confidence: 'medium' };
    if (ttl <= 255) return { os: 'Network Device (Router/Switch)', confidence: 'low' };
    return null;
  }

  static generateSecurityScore(openPorts, vulns) {
    let score = 100;

    for (const port of openPorts) {
      const risk = port.risk?.level;
      if (risk === 'critical') score -= 20;
      else if (risk === 'high') score -= 10;
      else if (risk === 'medium') score -= 5;
    }

    for (const vuln of vulns) {
      if (vuln.severity === 'CRITICAL') score -= 15;
      else if (vuln.severity === 'HIGH') score -= 10;
      else if (vuln.severity === 'MEDIUM') score -= 5;
    }

    return Math.max(0, Math.min(100, score));
  }

  static getScoreGrade(score) {
    if (score >= 90) return { grade: 'A', label: 'Excellent', color: '#22c55e' };
    if (score >= 75) return { grade: 'B', label: 'Good', color: '#84cc16' };
    if (score >= 60) return { grade: 'C', label: 'Fair', color: '#f59e0b' };
    if (score >= 40) return { grade: 'D', label: 'Poor', color: '#f97316' };
    return { grade: 'F', label: 'Critical', color: '#ef4444' };
  }

  static generateReport(scanResults) {
    const allVulns = [];
    let detectedOS = null;

    for (const port of scanResults.openPorts) {
      const banner = port.serviceInfo?.banner || port.banner || '';
      const service = port.service;

      const vulns = VulnChecker.checkService(service, banner);
      for (const v of vulns) {
        allVulns.push({ ...v, port: port.port, service });
      }

      if (!detectedOS) {
        detectedOS = VulnChecker.detectOS(service, banner);
      }
    }

    const score = VulnChecker.generateSecurityScore(scanResults.openPorts, allVulns);
    const grade = VulnChecker.getScoreGrade(score);

    return {
      securityScore: score,
      grade,
      detectedOS: detectedOS || 'Unknown',
      vulnerabilities: allVulns,
      totalVulns: allVulns.length,
      criticalCount: allVulns.filter((v) => v.severity === 'CRITICAL').length,
      highCount: allVulns.filter((v) => v.severity === 'HIGH').length,
      mediumCount: allVulns.filter((v) => v.severity === 'MEDIUM').length,
      lowCount: allVulns.filter((v) => v.severity === 'LOW').length
    };
  }
}

module.exports = { VulnChecker };
