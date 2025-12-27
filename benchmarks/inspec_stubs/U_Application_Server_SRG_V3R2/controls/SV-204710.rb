control 'SV-204710' do
  title 'The application server must implement cryptography mechanisms to protect the integrity of the remote access session.'
  desc 'Encryption is critical for protection of remote access sessions. If encryption is not being used for integrity, malicious users may gain the ability to modify the application server configuration. The use of cryptography for ensuring integrity of remote access sessions mitigates that risk.

Application servers utilize a web management interface and scripted commands when allowing remote access. Web access requires the use of TLS and scripted access requires using ssh or some other form of approved cryptography. Application servers must have a capability to enable a secure remote admin capability.

FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Review the application server documentation and configuration to ensure the application server is configured to use cryptography to protect the integrity of remote access sessions.

If the application server is not configured to implement cryptography mechanisms to protect the integrity of remote access sessions, this is a finding.'
  desc 'fix', 'Configure the application server to implement cryptography mechanisms to protect the integrity of the remote access session.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4830r282777_chk'
  tag severity: 'medium'
  tag gid: 'V-204710'
  tag rid: 'SV-204710r508029_rule'
  tag stig_id: 'SRG-APP-000015-AS-000010'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-4830r282778_fix'
  tag 'documentable'
  tag legacy: ['SV-46377', 'V-35090']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
