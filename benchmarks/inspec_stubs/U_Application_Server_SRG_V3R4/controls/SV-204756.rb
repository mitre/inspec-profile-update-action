control 'SV-204756' do
  title 'The application server must map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'The cornerstone of PKI is the private key used to encrypt or digitally sign information. The key by itself is a cryptographic value that does not contain specific user information, but the key can be mapped to a user.  Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

Application servers must provide the capability to utilize and meet requirements of the DoD Enterprise PKI infrastructure for application authentication.'
  desc 'check', 'Review application server documentation to ensure the application server provides a PKI integration capability that meets DoD PKI infrastructure requirements.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to utilize the DoD Enterprise PKI infrastructure.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4876r282915_chk'
  tag severity: 'medium'
  tag gid: 'V-204756'
  tag rid: 'SV-204756r879614_rule'
  tag stig_id: 'SRG-APP-000177-AS-000126'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-4876r282916_fix'
  tag 'documentable'
  tag legacy: ['SV-46612', 'V-35325']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
