control 'SV-215304' do
  title 'The AIX SSH daemon must be configured to not use host-based authentication.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(Check the SSH daemon configuration for allowed host-based authentication using command: 

# grep -i HostbasedAuthentication /etc/ssh/sshd_config | grep -v '^#'
HostbasedAuthentication no

If no lines are returned, or the returned "HostbasedAuthentication" directive contains "yes", this is a finding.)
  desc 'fix', 'Edit "/etc/ssh/sshd_config" and add or update the "HostbasedAuthentication" line as:
HostbasedAuthentication  no

Save the change and restart ssh daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16502r294363_chk'
  tag severity: 'medium'
  tag gid: 'V-215304'
  tag rid: 'SV-215304r508663_rule'
  tag stig_id: 'AIX7-00-002122'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16500r294364_fix'
  tag 'documentable'
  tag legacy: ['SV-101845', 'V-91747']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
