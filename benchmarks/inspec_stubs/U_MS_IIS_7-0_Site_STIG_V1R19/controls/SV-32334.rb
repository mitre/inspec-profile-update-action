control 'SV-32334' do
  title 'A private web server must utilize an approved TLS version.'
  desc 'Transport Layer Security (TLS) encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2 approved TLS version, and all non-FIPS-approved SSL versions must be disabled.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double click the SSL Settings Icon.
4. Ensure Require SSL and Require SSL 128-Bit are checked.

Note: If the Required SSL 128-Bit setting is not visible, the setting can be viewed by clicking the site under review and then opening the Configuration Editor. Switch to the section, the dropdown at the top of the configuration editor, system.webServer/security/access. The value for sslFlags should be ssl128.

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

The keys for TLS 1.0 do not require the "Enabled" value to be present, but if it is, it needs to be set to REG_DWORD 1, to enable TLS. If the "Enabled" value is present and set to 0, this is a finding.

TLS 1.1 and 1.2 are not supported in versions prior to IIS 7.5. If the version of IIS is prior to 7.5, the check for TLS 1.1 and 1.2 is NA.

TLS 1.1 and 1.2 are not enabled by default, therefore the following registry keys must exist and contain the the following values to enable TLS 1.1 and 1.2.

DisabledByDefault REG_DWORD 0
Enabled REG_DWORD 1 

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server

If any of the registry keys for TLS 1.1 or TLS 1.2 are not present or are not set correctly, this is a finding.

NOTE: In some cases the web servers are configured in an environment to support load balancing. This configuration most likely utilizes a content switch to control traffic to the various web servers. In this situation, the SSL certificate for the web sites may be installed on the content switch vs. the individual web sites. This solution is acceptable as long as the web servers are isolated from the general population LAN. We do not want users to have the ability to bypass the content switch to access the web sites.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double click the SSL Settings Icon.
4. Click the Require SSL and Require SSL 128-Bit check boxes.

Note: If the Required SSL 128-Bit setting is not visible, the setting can be set by clicking the site node and then opening the Configuration Editor. Switch to the section, the dropdown at the top of the configuration editor, system.webServer/security/access. Click the value beside the sslFlags and select ssl128 in the dropdown list.

5. Set the version of SSL/TLS by creating and setting the following registry to not allow anything lower than TLS. Ensure the following value exists in each of the keys: 

Enabled REG_DWORD 0 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\PCT 1.0\\Client 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\PCT 1.0\\Server 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\SSL 2.0\\Client 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\SSL 2.0\\Server 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\SSL 3.0\\Client 

HKey_Local_Machine\\System\\CurrentControlSet\\Control\\SecurityProviders \\SCHANNEL\\Protocols\\SSL 3.0\\Server 

The keys for TLS 1.0 do not require the Enabled value to be present, but if it is, it needs to be set to REG_DWORD 1, to enable TLS.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32740r8_chk'
  tag severity: 'medium'
  tag gid: 'V-2262'
  tag rid: 'SV-32334r5_rule'
  tag stig_id: 'WG340 IIS7'
  tag gtitle: 'WG340'
  tag fix_id: 'F-29067r5_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
