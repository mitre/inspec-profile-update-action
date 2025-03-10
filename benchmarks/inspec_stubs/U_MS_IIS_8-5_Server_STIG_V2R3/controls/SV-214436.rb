control 'SV-214436' do
  title 'An IIS 8.5 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc 'Transport Layer Security (TLS) encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2-approved TLS version, and all non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', %q(Access the IIS 8.5 Web Server.

Access an administrator command prompt and type "regedit <enter>" to access the server's registry.

Navigate to:
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server

Verify a REG_DWORD value of "1" for "Enabled"

Navigate to:
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server

Verify a REG_DWORD value of "1" for "DisabledByDefault" for each protocol.

Verify a REG_DWORD value of "0" for "Enabled" for each protocol.


If any of the respective registry paths do not exist or are configured with the wrong value, this is a finding.)
  desc 'fix', %q(Access the IIS 8.5 Web Server.

Access an administrator command prompt and type "regedit <enter>" to access the server's registry.

Navigate to the following registry paths and configure the  REG_DWORD with the appropriate values:

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server 

With a REG_DWORD value of "1" for "Enabled"

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server

HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server

With a REG_DWORD value of "1" for "DisabledByDefault"

With a REG_DWORD value of "0" for "Enabled")
  impact 0.7
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15646r695289_chk'
  tag severity: 'high'
  tag gid: 'V-214436'
  tag rid: 'SV-214436r695334_rule'
  tag stig_id: 'IISW-SV-000153'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-15644r695333_fix'
  tag 'documentable'
  tag legacy: ['SV-91455', 'V-76759']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
