control 'SV-32483' do
  title 'Public web servers must use TLS if authentication is required.'
  desc 'Transport Layer Security (TLS) is optional for a public web server.  However, if authentication is being performed, then the use of the TLS protocol is required.

Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure.  Using TLS along with DoD PKI certificates for encryption of the authentication data protects the information from being accessed by all parties on the network.  To further protect the authentication data, the web server must use a FIPS 140-2 approved TLS version and all non-FIPS-approved SSL versions must be disabled.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater.  NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click SSL icon.
4. Ensure Require SSL and Require 128-bit SSL are checked. 

Note:  If the Require SSL 128-Bit setting is not visible, the setting can be viewed by clicking the site under review and then opening the Configuration Editor.  Switch to the section, the dropdown at the top of the configuration editor, system.webServer/security/access.  The value for sslFlags should be ssl128.

If not, this is a finding.

If the site requires SSL and 128-bit encryption, then the version of SSL\\TLS also needs to be verified. 

The following registry keys need to exist and be set to not allow anything lower than TLS. This can be accomplished by ensuring the following value exists in each of the keys: 

Enabled REG_DWORD 0 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\PCT 1.0\\Client 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\PCT 1.0\\Server 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\SSL 2.0\\Client 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\SSL 2.0\\Server 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\SSL 3.0\\Client 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\SSL 3.0\\Server 

If these keys are not set to a DWORD value of 0, this is a finding. 

If the keys do not contain the value "Enabled", this would also be a finding. 

The keys for TLS 1.0 do not require the "Enabled" value to be present, but if it is, it needs to be set to REG_DWORD 1, to enable TLS.  If the "Enabled" value is present and set to 0, this is a finding.

TLS 1.1 and 1.2 are not supported in versions prior to IIS 7.5.  If the version of IIS is prior to 7.5, the check for TLS 1.1 and 1.2 is NA.

TLS 1.1 and 1.2 are not enabled by default, therefore the following registry keys must exist and contain the the following values to enable TLS 1.1 and 1.2.

DisabledByDefault REG_DWORD 0
Enabled REG_DWORD 1 

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server

If any of the registry keys for TLS 1.1 or TLS 1.2 are not present or are not set correctly, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click SSL icon.
4. Check the Require SSL and Require 128-bit SSL check box.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32799r5_chk'
  tag severity: 'medium'
  tag gid: 'V-13694'
  tag rid: 'SV-32483r3_rule'
  tag stig_id: 'WG342 IIS7'
  tag gtitle: 'WG342'
  tag fix_id: 'F-29075r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
