control 'SV-220504' do
  title 'The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Verify that FIPS mode is enabled as shown in the example below:

fips mode enable

Note: Cisco NX-OS software supports only SSH version 2 (SSHv2). Beginning in Cisco NX-OS Release 5.1, SSH runs in FIPS mode. Source: Cisco Nexus 7000 Series NX-OS Security Configuration Guide, Release 6.x

If the switch is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions, this is a finding.'
  desc 'fix', 'Enable fips mode via the command fips mode enable.'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22219r539233_chk'
  tag severity: 'high'
  tag gid: 'V-220504'
  tag rid: 'SV-220504r879785_rule'
  tag stig_id: 'CISC-ND-001210'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-22208r539234_fix'
  tag 'documentable'
  tag legacy: ['SV-110657', 'V-101553']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
