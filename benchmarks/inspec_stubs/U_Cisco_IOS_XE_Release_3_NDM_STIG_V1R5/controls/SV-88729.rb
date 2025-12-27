control 'SV-88729' do
  title 'Applications used for nonlocal maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
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
  tag check_id: 'C-74145r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74055'
  tag rid: 'SV-88729r2_rule'
  tag stig_id: 'CISR-ND-000118'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-80597r3_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
