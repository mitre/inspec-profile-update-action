control 'SV-204830' do
  title 'The application server must generate log records for all account creations, modifications, disabling, and termination events.'
  desc 'The maintenance of user accounts is a key activity within the system to determine access and privileges.  Through changes to accounts, an attacker can create an account for persistent access, modify an account to elevate privileges or terminate/disable an account(s) to cause a DoS for user(s).  To be able to track and investigate these actions, log records must be generated for any account modification functions.

Application servers either provide a local user store, or they can integrate with enterprise user stores like LDAP.  As such, the application server must be able to generate log records on account creation, modification, disabling, and termination.'
  desc 'check', 'Review the application server documentation and the system configuration to determine if the application server generates log records when accounts are created, modified, disabled, or terminated.

If the application server does not generate log records for account creation, modification, disabling, and termination, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records when accounts are created, modified, disabled, or terminated.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4950r283131_chk'
  tag severity: 'medium'
  tag gid: 'V-204830'
  tag rid: 'SV-204830r879880_rule'
  tag stig_id: 'SRG-APP-000509-AS-000234'
  tag gtitle: 'SRG-APP-000509'
  tag fix_id: 'F-4950r283132_fix'
  tag 'documentable'
  tag legacy: ['SV-71761', 'V-57485']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
