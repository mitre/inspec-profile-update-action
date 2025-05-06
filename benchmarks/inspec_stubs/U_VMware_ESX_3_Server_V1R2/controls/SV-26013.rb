control 'SV-26013' do
  title 'All shell files must not have extended ACLs.'
  desc 'Shells with world/group-write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'check', 'If /etc/shells exists, check the permissions of each shell referenced.
# cat /etc/shells | xargs -n1 ls -lL

Otherwise, check any shells found on the system.
# find / -name "*sh" | xargs -n1 ls -lL

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the shell file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27549r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22366'
  tag rid: 'SV-26013r1_rule'
  tag stig_id: 'GEN002230'
  tag gtitle: 'GEN002230'
  tag fix_id: 'F-26219r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
