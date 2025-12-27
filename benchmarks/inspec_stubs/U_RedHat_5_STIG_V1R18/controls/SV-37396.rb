control 'SV-37396' do
  title 'All shell files must be owned by root or bin.'
  desc 'If shell files are owned by users other than root or bin, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'Check the ownership of the system shells.
# cat /etc/shells | xargs -n1 ls -l
If any shell is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the shell with incorrect ownership.
# chown root <shell>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-921'
  tag rid: 'SV-37396r1_rule'
  tag stig_id: 'GEN002200'
  tag gtitle: 'GEN002200'
  tag fix_id: 'F-31328r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
