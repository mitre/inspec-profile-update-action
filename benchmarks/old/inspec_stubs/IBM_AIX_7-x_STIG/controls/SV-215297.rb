control 'SV-215297' do
  title 'AIX must turn on SSH daemon privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'check', %q(Check the SSH daemon configuration for the "UsePrivilegeSeparation" setting using command: 

# grep -i UsePrivilegeSeparation  /etc/ssh/sshd_config | grep -v '^#' 
UsePrivilegeSeparation yes

If the setting is not present or the setting is "no", this is a finding.)
  desc 'fix', 'Edit the "/etc/sshd/sshd_config" file and add the following line:
UsePrivilegeSeparation yes

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16495r294342_chk'
  tag severity: 'medium'
  tag gid: 'V-215297'
  tag rid: 'SV-215297r508663_rule'
  tag stig_id: 'AIX7-00-002114'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16493r294343_fix'
  tag 'documentable'
  tag legacy: ['SV-101823', 'V-91725']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
