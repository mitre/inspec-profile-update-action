control 'SV-227694' do
  title 'All shell files must be owned by root or bin.'
  desc 'If shell files are owned by users other than root or bin, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'Check the ownership of the system shells.
# cat /etc/shells | xargs -n1 ls -lL
If any shell is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the shell with incorrect ownership.
# chown root <shell>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29856r488663_chk'
  tag severity: 'medium'
  tag gid: 'V-227694'
  tag rid: 'SV-227694r603266_rule'
  tag stig_id: 'GEN002200'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29844r488664_fix'
  tag 'documentable'
  tag legacy: ['V-921', 'SV-921']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
