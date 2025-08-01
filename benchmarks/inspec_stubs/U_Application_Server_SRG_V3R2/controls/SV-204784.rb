control 'SV-204784' do
  title 'The application server must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Restricting non-privileged users also prevents an attacker, who has gained access to a non-privileged account, from elevating privileges, creating accounts, and performing system checks and maintenance.'
  desc 'check', 'Review application server documentation and configuration to verify that non-privileged users cannot access or execute privileged functions.

Have a user logon as a non-privileged user and attempt to execute privileged functions.

If the user is capable of executing privileged functions, this is a finding.'
  desc 'fix', 'Configure the application server to deny non-privileged users access to and execution of privileged functions.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4904r282999_chk'
  tag severity: 'medium'
  tag gid: 'V-204784'
  tag rid: 'SV-204784r508029_rule'
  tag stig_id: 'SRG-APP-000340-AS-000185'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-4904r283000_fix'
  tag 'documentable'
  tag legacy: ['V-57399', 'SV-71671']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
