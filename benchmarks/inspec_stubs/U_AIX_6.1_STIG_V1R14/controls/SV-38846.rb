control 'SV-38846' do
  title 'All shell files must have mode 0755 or less permissive.'
  desc 'Shells with world/group write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'check', 'Obtain a list of system shells from /etc/security/login.cfg and check the permissions of these shells.
Procedure:
#grep shells /etc/security/login.cfg | grep -v \\* | cut -f 2 -d = | sed s/,/\\ /g | xargs -n1 ls -l
If any shell has a mode more permissive than 0755, this is a finding.

Obtain a list of  system shells from /etc/shells and check the  ownership of these shells.
Procedure:
#cat /etc/shells | xargs -n1 ls -l

If any shell has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the shell.
# chmod 0755 < shell >'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37839r1_chk'
  tag severity: 'high'
  tag gid: 'V-922'
  tag rid: 'SV-38846r1_rule'
  tag stig_id: 'GEN002220'
  tag gtitle: 'GEN002220'
  tag fix_id: 'F-33102r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
