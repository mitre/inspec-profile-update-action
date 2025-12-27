control 'SV-256841' do
  title 'Compliance Guardian must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications and is not applicable to virtual private network (VPN) devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation on either DOD-only or on public-facing servers.

'
  desc 'check', %q(Check the .Net Framework version on Compliance Guardian servers.
- On servers where Compliance Guardian is installed, open "Registry Editor".
- Refer to the Microsoft document to verify the .Net Framework version supports TLS 1.2. The Microsoft Document URL is: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client#bkmk_net.
- .NET Framework 4.6.2 or later supports TLS 1.2 natively.

If the .Net Framework version doesn't support TLS 1.2, this is a finding.

Check the Compliance Guardian servers only have TLS 1.2 protocol enabled.
- On the Compliance Guardian servers, open "Registry Editor".
- Navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols.
- Verify TLS 1.0, TLS 1.1, and any SSL protocols are not enabled.

If TLS 1.0, TLS 1.1, or any SSL protocols are enabled, this is a finding.

Check that Compliance Guardian servers have strong cryptography setting enabled.
- On the Compliance Guardian servers, open "Registry Editor".
- Navigate to HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319.
Verify "SystemDefaultTlsVersions" = dword:00000001 and "SchUseStrongCrypto" = dword:00000001, otherwise this is a finding.)
  desc 'fix', 'Consult Microsoft documentation and ensure the .Net Framework on Compliance Guardian servers is a version that supports TLS 1.2. Update if necessary.

Configure the Compliance Guardian servers to enable TLS 1.2 protocol only.
- On the Compliance Guardian servers, open "Registry Editor".
- Navigate to HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols.
- Disable TLS 1.0, TLS 1.1, and any SSL protocols, if present.

Configure the Compliance Guardian servers to enable strong cryptography settings.
- On the Compliance Guardian servers, open "Registry Editor".
- Navigate to HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319 and verify:
"SystemDefaultTlsVersions" = dword:00000001
"SchUseStrongCrypto" = dword:00000001'
  impact 0.7
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60516r890131_chk'
  tag severity: 'high'
  tag gid: 'V-256841'
  tag rid: 'SV-256841r890133_rule'
  tag stig_id: 'APCG-00-000010'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-60459r890132_fix'
  tag satisfies: ['SRG-APP-000014', 'SRG-APP-000560', 'SRG-APP-000565', 'SRG-APP-000645']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000382', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'CM-7 b', 'AC-17 (2)']
end
