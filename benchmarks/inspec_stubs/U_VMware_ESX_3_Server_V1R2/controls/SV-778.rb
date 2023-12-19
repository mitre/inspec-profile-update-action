control 'SV-778' do
  title 'The system must prevent the root account from directly logging in except from the system console.'
  desc 'Limiting the root account direct logins to only system consoles protects the root account from direct unauthorized access from a non-console device.'
  desc 'check', 'Verify the system only allows root account logins from the system console.'
  desc 'fix', 'Configure the system to only allow root logins from the system console.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28065r1_chk'
  tag severity: 'medium'
  tag gid: 'V-778'
  tag rid: 'SV-778r2_rule'
  tag stig_id: 'GEN000980'
  tag gtitle: 'GEN000980'
  tag fix_id: 'F-24416r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
