control 'SV-38502' do
  title 'All shell files must have mode 0755 or less permissive.'
  desc 'Shells with world/group-write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'check', 'If /etc/shells exists, check the group ownership of each shell referenced.
# cat /etc/shells | xargs -n1 ls -lL

Otherwise, check any shells found on the system.
# find / -name "*sh" | xargs -n1 ls -lL

If a shell has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the shell.
# chmod 0755 <shell>'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36413r1_chk'
  tag severity: 'high'
  tag gid: 'V-922'
  tag rid: 'SV-38502r1_rule'
  tag stig_id: 'GEN002220'
  tag gtitle: 'GEN002220'
  tag fix_id: 'F-31751r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
