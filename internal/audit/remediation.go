package audit

import "strings"

var remediationDB = map[string]string{
	"CVE-2023-38408": "Update OpenSSH to 9.3p2 or later. This critical flaw allows remote code execution via the SSH agent.",
	"CVE-2023-51385": "Update OpenSSH to 9.6 or later. Exploitable via crafted hostnames containing shell metacharacters.",
	"CVE-2024-6387":  "Update OpenSSH to 9.8p1 or later immediately. This is a critical unauthenticated RCE (regreSSHion).",

	"CVE-2023-44487": "Update Nginx to 1.25.3+ or apply the ngx_http_v2 patch. This is the HTTP/2 Rapid Reset DoS attack.",
	"CVE-2021-23017": "Update Nginx to 1.21.0+. Off-by-one heap write via crafted DNS response.",
	"CVE-2019-9511":  "Update Nginx to 1.17.3+. HTTP/2 Data Dribble DoS vulnerability.",

	"CVE-2021-41773": "Update Apache immediately to 2.4.51+. Path traversal and RCE vulnerability actively exploited in the wild.",
	"CVE-2021-42013": "Update Apache to 2.4.51+. Incomplete fix for CVE-2021-41773; still exploitable for RCE.",
	"CVE-2022-31813": "Update Apache to 2.4.55+. Forwarded headers bypass allowing authentication bypass.",

	"CVE-2023-21980": "Update MySQL to 8.0.33+ or 5.7.42+. Remote code execution vulnerability in MySQL Server.",
	"CVE-2022-21595": "Update MySQL to 8.0.28+. Allows high-privilege attacker to cause complete denial of service.",
	"CVE-2021-2307":  "Update MySQL to 8.0.24+. Unauthenticated attacker can read files from the MySQL server host.",

	"CVE-2023-2454":  "Update PostgreSQL to 15.3, 14.8, 13.11, 12.15, or 11.20. Extension scripts bypass security restrictions.",
	"CVE-2022-2625":  "Update PostgreSQL to 14.5+. Extension scripts can be used to escalate privileges.",
	"CVE-2021-23214": "Update PostgreSQL to 14.1+. Man-in-the-middle attack possible via GSSAPI downgrade.",

	"CVE-2023-41056": "Update Redis to 7.2.3, 7.0.15, or 6.2.14. Heap overflow via specially crafted LMPOP command.",
	"CVE-2022-0543":  "Update Redis to 6.2.6+. Lua sandbox escape allowing remote code execution.",
	"CVE-2021-32762": "Update Redis to 6.2.6+. Heap overflow in redis-check-aof and redis-check-rdb tools.",

	"CVE-2021-20330": "Update MongoDB to 4.4.4+ or 4.2.13+. Malformed BSON objects can cause server crash.",
	"CVE-2019-2386":  "Update MongoDB to 4.0.9+. User management commands may allow privilege escalation.",

	"CVE-2017-0144":  "Apply MS17-010 patch immediately. This is EternalBlue — the exploit behind WannaCry. Disable SMBv1.",
	"CVE-2020-0796":  "Apply KB4551762 patch immediately. SMBGhost — unauthenticated RCE in SMBv3 compression.",
	"CVE-2021-34527": "Apply July 2021 Windows patches immediately. PrintNightmare — RCE via Windows Print Spooler.",

	"CVE-2019-0708": "Apply MS19-0708 patch immediately. BlueKeep — critical pre-auth RCE in RDP. Block port 3389 externally.",
	"CVE-2019-1181": "Apply August 2019 patches. DejaBlue — wormable pre-auth RCE in RDP similar to BlueKeep.",

	"CVE-2015-3306": "Update ProFTPD to 1.3.5a+. Backdoor command allows unauthenticated filesystem access.",

	"CVE-2011-4862": "Disable Telnet immediately and replace with SSH. All Telnet traffic is transmitted in plaintext.",
}

var productFallbacks = map[string]string{
	"openssh":    "Keep OpenSSH updated to the latest stable release. Disable password authentication and use SSH keys only.",
	"nginx":      "Keep Nginx updated to the latest stable branch (1.24.x stable or 1.25.x mainline). Review your server_tokens off setting.",
	"apache":     "Keep Apache updated to 2.4.58+. Disable unused modules and ensure Directory listings are off.",
	"mysql":      "Keep MySQL updated. Ensure MySQL is not exposed publicly (bind to 127.0.0.1). Use strong passwords and remove anonymous users.",
	"mariadb":    "Keep MariaDB updated. Bind to localhost and restrict remote access. Run mysql_secure_installation.",
	"postgresql": "Keep PostgreSQL updated. Restrict pg_hba.conf to trusted hosts only. Avoid superuser connections from apps.",
	"redis":      "Bind Redis to 127.0.0.1 in redis.conf. Enable requirepass. Never expose Redis publicly — it has no auth by default.",
	"mongodb":    "Enable MongoDB authentication (--auth). Bind to localhost unless remote access is required. Keep updated.",
	"smb":        "Disable SMBv1 immediately via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Apply all Windows patches.",
	"rdp":        "Restrict RDP (port 3389) to VPN or trusted IPs only via firewall rules. Enable Network Level Authentication (NLA).",
	"ftp":        "Consider replacing FTP with SFTP (SSH file transfer). If FTP is required, use FTPS and restrict to trusted IPs.",
	"telnet":     "Disable Telnet immediately — all traffic is plaintext. Use SSH instead. Block port 23 at the firewall.",
	"vnc":        "Never expose VNC publicly. Tunnel VNC over SSH. Use a strong VNC password and restrict via firewall.",
}

func Remediation(cveID, product string) string {
	if fix, ok := remediationDB[cveID]; ok {
		return fix
	}

	lower := strings.ToLower(product)
	for keyword, advice := range productFallbacks {
		if strings.Contains(lower, keyword) {
			return advice
		}
	}

	return "Update " + product + " to the latest stable version and consult the vendor's security advisories for patch details."
}
