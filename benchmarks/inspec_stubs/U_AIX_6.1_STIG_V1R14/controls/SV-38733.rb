control 'SV-38733' do
  title 'All run control scripts must have no extended ACLs.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', 'Verify run control scripts have no extended ACLs.
Check if extended permissions are disabled.
# ls -l /etc/rc*
# aclget /etc/rc* 
# aclget /etc/init.d
If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the run control script(s) and disable extended permissions.

#acledit <directory>/<file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37150r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22353'
  tag rid: 'SV-38733r1_rule'
  tag stig_id: 'GEN001590'
  tag gtitle: 'GEN001590'
  tag fix_id: 'F-32415r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
