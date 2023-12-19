control 'SV-218671' do
  title 'The system must use an access control program.'
  desc 'Access control programs (such as TCP_WRAPPERS) provide the ability to enhance system security posture.'
  desc 'check', 'The tcp_wrappers package is provided with the operating system.  Other access control programs may be available but will need to be checked manually.

Determine if tcp_wrappers is installed.
# rpm -qa | grep tcp_wrappers
If no package is listed, this is a finding.'
  desc 'fix', 'Install and configure the tcp_wrappers package.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20146r556427_chk'
  tag severity: 'medium'
  tag gid: 'V-218671'
  tag rid: 'SV-218671r603259_rule'
  tag stig_id: 'GEN006580'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20144r556428_fix'
  tag 'documentable'
  tag legacy: ['V-940', 'SV-63577']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
