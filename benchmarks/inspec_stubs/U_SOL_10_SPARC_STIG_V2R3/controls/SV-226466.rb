control 'SV-226466' do
  title 'All non-interactive/automated processing account passwords must be changed at least once per year or be locked.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password. Locking the password for non-interactive and automated processing accounts is preferred as it removes the possibility of accessing the account by a password. On some systems, locking the passwords of these accounts may prevent the account from functioning properly. Passwords for non-interactive/automated processing accounts must not be used for direct logon to the system.'
  desc 'check', 'Ask the SA if there are any automated processing accounts on the system. If there are automated processing accounts on the system, ask the SA if the passwords for those automated accounts are changed at least once a year. If SA indicates passwords for automated processing accounts are not changed once per year, this is a finding.'
  desc 'fix', 'Implement or establish procedures to change the passwords of automated processing accounts at least once per year.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28627r482774_chk'
  tag severity: 'medium'
  tag gid: 'V-226466'
  tag rid: 'SV-226466r603265_rule'
  tag stig_id: 'GEN000740'
  tag gtitle: 'SRG-OS-000076'
  tag fix_id: 'F-28615r482775_fix'
  tag 'documentable'
  tag legacy: ['SV-12478', 'V-11977']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
