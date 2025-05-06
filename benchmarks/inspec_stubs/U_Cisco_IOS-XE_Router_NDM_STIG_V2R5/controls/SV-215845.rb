control 'SV-215845' do
  title 'The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement.

SSH Example

ip ssh version 2
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr

If the router is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the Cisco router to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm as shown in the examples below.

SSH Example

R1(config)#ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17084r860789_chk'
  tag severity: 'high'
  tag gid: 'V-215845'
  tag rid: 'SV-215845r860791_rule'
  tag stig_id: 'CISC-ND-001210'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-17082r860790_fix'
  tag 'documentable'
  tag legacy: ['SV-105467', 'V-96329']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
