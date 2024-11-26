control 'SV-227603' do
  title 'The system must prevent the root account from directly logging in except from the system console.'
  desc 'Limiting the root account direct logins to only system consoles protects the root account from direct unauthorized access from a non-console device.'
  desc 'check', 'Check the CONSOLE setting in /etc/default/login
# grep CONSOLE /etc/default/login
If CONSOLE is set to a value other than /dev/console, this is a finding.'
  desc 'fix', 'Edit the /etc/default/login file and uncomment the line containing /dev/console if it is commented out.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29765r488366_chk'
  tag severity: 'medium'
  tag gid: 'V-227603'
  tag rid: 'SV-227603r603266_rule'
  tag stig_id: 'GEN000980'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-29753r488367_fix'
  tag 'documentable'
  tag legacy: ['V-778', 'SV-27143']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
