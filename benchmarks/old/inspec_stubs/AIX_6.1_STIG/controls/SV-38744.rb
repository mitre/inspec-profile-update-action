control 'SV-38744' do
  title 'All shell files must not have extended ACLs.'
  desc 'Shells with world/group write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'check', 'Check the permissions of each shell referenced in /etc/shells.
Procedure:
# cat /etc/shells 

For each shell listed,  run aclget <shell path>
#aclget <shell>

Check the permissions of each shell referenced in /etc/security/login.cfg.
Procedure:
#grep shells /etc/security/login.cfg
For each shell listed, run aclget <shell path>
# aclget  <shell>

Otherwise, check any shells found on the system.
# find / -name "*sh

#aclget <directory>/<file> 

If extended permissions are enabled on any shell,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the shell file(s) and disable extended permissions.

#acledit <directory>/<file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22366'
  tag rid: 'SV-38744r1_rule'
  tag stig_id: 'GEN002230'
  tag gtitle: 'GEN002230'
  tag fix_id: 'F-32458r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
