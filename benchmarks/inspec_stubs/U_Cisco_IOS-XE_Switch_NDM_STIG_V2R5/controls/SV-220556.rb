control 'SV-220556' do
  title 'The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement.

ip ssh version 2
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr 

If the switch is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm as shown in the example below:

SW1(config)#iip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22271r508612_chk'
  tag severity: 'high'
  tag gid: 'V-220556'
  tag rid: 'SV-220556r879785_rule'
  tag stig_id: 'CISC-ND-001210'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-22260r508613_fix'
  tag 'documentable'
  tag legacy: ['SV-110567', 'V-101463']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
