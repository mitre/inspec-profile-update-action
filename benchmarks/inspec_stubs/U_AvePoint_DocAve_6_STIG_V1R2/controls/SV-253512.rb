control 'SV-253512' do
  title 'DocAve must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications and is not applicable to virtual private network (VPN) devices.

DocAve uses HTTPS and NetTcp protocols as the underlying security protocol and thus is in scope for this requirement.'
  desc 'check', %q(Check the .Net Framework version on DocAve servers.
- On the servers where DocAve is installed, open Registry Editor.
- Refer to the official Microsoft document to verify the .Net Framework version supports TLS 1.2. The official Microsoft Document URL is: https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client#bkmk_net.
- .NET Framework 4.6.2 or later supports TLS 1.2 inherently.

If the .Net Framework version doesn't support TLS 1.2, this is a finding.

Check that DocAve servers only have TLS 1.2 protocol enabled.
- On the DocAve servers, open Registry Editor.
- Navigate to: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols.
- Verify TLS 1.0, TLS 1.1, and any SSL protocols are not enabled.

If TLS 1.0, TLS 1.1, or any SSL protocols are enabled, this is a finding.

Check that DocAve servers have strong cryptography setting enabled.
- On the DocAve servers, open Registry Editor.
- Navigate to: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319.
- Verify "SystemDefaultTlsVersions" = dword:00000001 and "SchUseStrongCrypto" = dword:00000001, otherwise this is a finding.)
  desc 'fix', 'Consult the Microsoft documentation and ensure the .Net Framework on DocAve servers uses a version that supports TLS 1.2. Update if necessary.

Configure the DocAve servers to enable TLS 1.2 protocol only:
- On the DocAve servers, open Registry Editor.
- Navigate to: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols.
- Disable TLS 1.0, TLS 1.1, and any SSL protocols if present.

Configure the DocAve servers to enable strong cryptography setting.
- On the DocAve servers, open Registry Editor.
- Navigate to: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319 and verify:
"SystemDefaultTlsVersions" = dword:00000001
"SchUseStrongCrypto" = dword:00000001'
  impact 0.7
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56964r836509_chk'
  tag severity: 'high'
  tag gid: 'V-253512'
  tag rid: 'SV-253512r836511_rule'
  tag stig_id: 'DCAV-00-000006'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-56915r836510_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
