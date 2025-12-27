control 'SV-940' do
  title 'The system must use an access control program.'
  desc 'Access control programs (such as TCP_WRAPPERS) provide the ability to enhance system security posture.'
  desc 'check', 'Determine if TCP_WRAPPERS is installed and used.  If it is not, this is a finding.'
  desc 'fix', 'Install and configure the TCP_WRAPPERS software.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-887r2_chk'
  tag severity: 'medium'
  tag gid: 'V-28457'
  tag rid: 'SV-940r2_rule'
  tag stig_id: 'GEN006580'
  tag gtitle: 'GEN006580'
  tag fix_id: 'F-1094r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000104']
  tag nist: ['AT-1 a 2']
end
