control 'SV-88727' do
  title 'Applications used for nonlocal maintenance sessions must implement cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.'
  desc 'check', 'Verify that the Cisco IOS XE router is using SSHv2 for remote access.

The configuration should look like the example below:

ip ssh version 2
!
line vty 0 98
transport input ssh

If secure applications are not being used, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to use SSHv2 for remote access.

The configuration should look like the example below:

ip ssh version 2
!
line vty 0 98
transport input ssh'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74143r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74053'
  tag rid: 'SV-88727r2_rule'
  tag stig_id: 'CISR-ND-000117'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-80595r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
