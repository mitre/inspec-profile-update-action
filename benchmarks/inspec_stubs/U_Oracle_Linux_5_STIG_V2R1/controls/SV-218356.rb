control 'SV-218356' do
  title 'All shell files must not have extended ACLs.'
  desc 'Shells with world/group write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'check', %q(If /etc/shells exists, check the permissions of each shell referenced.
# cat /etc/shells | xargs -n1 ls -lL

Otherwise, check any shells found on the system.
# find / -name "*sh" | xargs -n1 ls -lL

If the permissions include a '+', the file has an extended ACL. 

If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [shell]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19831r569035_chk'
  tag severity: 'medium'
  tag gid: 'V-218356'
  tag rid: 'SV-218356r603259_rule'
  tag stig_id: 'GEN002230'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19829r569036_fix'
  tag 'documentable'
  tag legacy: ['V-22366', 'SV-63017']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
