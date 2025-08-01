control 'SV-218353' do
  title 'All shell files must be owned by root or bin.'
  desc 'If shell files are owned by users other than root or bin, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'Check the ownership of the system shells.
# cat /etc/shells | xargs -n1 ls -l
If any shell is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the shell with incorrect ownership.
# chown root <shell>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19828r561788_chk'
  tag severity: 'medium'
  tag gid: 'V-218353'
  tag rid: 'SV-218353r603259_rule'
  tag stig_id: 'GEN002200'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19826r561789_fix'
  tag 'documentable'
  tag legacy: ['V-921', 'SV-63677']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
