control 'SV-226477' do
  title 'The system must prevent the root account from directly logging in except from the system console.'
  desc 'Limiting the root account direct logins to only system consoles protects the root account from direct unauthorized access from a non-console device.'
  desc 'check', 'Check the CONSOLE setting in /etc/default/login
# grep CONSOLE /etc/default/login
If CONSOLE is set to a value other than /dev/console, this is a finding.'
  desc 'fix', 'Edit the /etc/default/login file and uncomment the line containing /dev/console if it is commented out.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28638r482816_chk'
  tag severity: 'medium'
  tag gid: 'V-226477'
  tag rid: 'SV-226477r603265_rule'
  tag stig_id: 'GEN000980'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-28626r482817_fix'
  tag 'documentable'
  tag legacy: ['SV-27143', 'V-778']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
