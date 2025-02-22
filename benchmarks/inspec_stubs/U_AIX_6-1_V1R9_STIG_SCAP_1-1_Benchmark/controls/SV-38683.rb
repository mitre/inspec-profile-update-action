control 'SV-38683' do
  title 'The system must prevent the root account from directly logging in except from the system console.'
  desc 'Limiting the root account direct logins to only system consoles protects the root account from direct unauthorized access from a non-console device.'
  desc 'fix', 'The root account can be protected from non-console device logins by setting rlogin = false in the root: stanza of the /etc/security/user file.
 
#chsec -f /etc/security/user -s root -a rlogin=false'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-778'
  tag rid: 'SV-38683r1_rule'
  tag stig_id: 'GEN000980'
  tag gtitle: 'GEN000980'
  tag fix_id: 'F-32196r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
