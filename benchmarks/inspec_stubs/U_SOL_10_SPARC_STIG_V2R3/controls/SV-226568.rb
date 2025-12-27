control 'SV-226568' do
  title 'All shell files must be owned by root or bin.'
  desc 'If shell files are owned by users other than root or bin, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'Check the ownership of the system shells.
# cat /etc/shells | xargs -n1 ls -lL
If any shell is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the shell with incorrect ownership.
# chown root <shell>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28729r483113_chk'
  tag severity: 'medium'
  tag gid: 'V-226568'
  tag rid: 'SV-226568r603265_rule'
  tag stig_id: 'GEN002200'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28717r483114_fix'
  tag 'documentable'
  tag legacy: ['SV-921', 'V-921']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
