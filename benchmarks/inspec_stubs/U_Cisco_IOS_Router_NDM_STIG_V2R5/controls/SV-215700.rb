control 'SV-215700' do
  title 'The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement.

SSH Example

ip ssh version 2
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr

HTTPS Example

ip http secure-server
ip http secure-ciphersuite aes-128-cbc-sha 
ip http secure-client-auth
ip http secure-trustpoint CA_XXX

If the router is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the Cisco router to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm as shown in the examples below.

SSH Example

R1(config)#ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
                         
HTTPS Example

R2(config)#ip http secure-ciphersuite aes-128-cbc-sha'
  impact 0.7
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16894r835054_chk'
  tag severity: 'high'
  tag gid: 'V-215700'
  tag rid: 'SV-215700r879785_rule'
  tag stig_id: 'CISC-ND-001210'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-16892r835055_fix'
  tag 'documentable'
  tag legacy: ['V-96147', 'SV-105285']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
