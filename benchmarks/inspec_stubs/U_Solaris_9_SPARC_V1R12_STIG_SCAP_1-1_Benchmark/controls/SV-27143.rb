control 'SV-27143' do
  title 'The system must prevent the root account from directly logging in except from the system console.'
  desc 'Limiting the root account direct logins to only system consoles protects the root account from direct unauthorized access from a non-console device.'
  desc 'fix', 'Edit the /etc/default/login file and uncomment the line containing /dev/console if it is commented out.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-778'
  tag rid: 'SV-27143r1_rule'
  tag stig_id: 'GEN000980'
  tag gtitle: 'GEN000980'
  tag fix_id: 'F-24417r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSD-2, ECPA-1'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
