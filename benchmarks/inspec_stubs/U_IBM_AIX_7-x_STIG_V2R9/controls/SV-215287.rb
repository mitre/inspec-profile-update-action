control 'SV-215287' do
  title 'On AIX, the SSH server must not permit root logins using remote access programs.'
  desc "Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password."
  desc 'check', 'Determine if the SSH daemon is configured to disable root logins:
# grep -iE "PermitRootLogin[[:blank:]]*no" /etc/ssh/sshd_config | grep -v \\#

If the above command displays a line, the root login is disabled.

If the root login is not disabled, this is a finding.'
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file to have the following line and save the change: 
PermitRootLogin no

Restart SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16485r294312_chk'
  tag severity: 'medium'
  tag gid: 'V-215287'
  tag rid: 'SV-215287r508663_rule'
  tag stig_id: 'AIX7-00-002102'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16483r294313_fix'
  tag 'documentable'
  tag legacy: ['V-91577', 'SV-101675']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
