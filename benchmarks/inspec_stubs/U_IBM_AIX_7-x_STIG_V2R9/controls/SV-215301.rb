control 'SV-215301' do
  title 'AIX must turn off TCP forwarding for the SSH daemon.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.'
  desc 'check', %q(If TCP forwarding is approved for use by the ISSO, this is not applicable.

Check the SSH daemon configuration for the "AllowTcpForwarding" directive using command: 

# grep -i AllowTcpForwarding /etc/ssh/sshd_config | grep -v '^#' 
AllowTcpForwarding no

If the setting is not present or the setting is "yes", this is a finding.)
  desc 'fix', 'Edit the "/etc/sshd/sshd_config" file to add the following line and save the change:
AllowTcpForwarding no

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16499r294354_chk'
  tag severity: 'medium'
  tag gid: 'V-215301'
  tag rid: 'SV-215301r508663_rule'
  tag stig_id: 'AIX7-00-002118'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16497r294355_fix'
  tag 'documentable'
  tag legacy: ['V-91733', 'SV-101831']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
