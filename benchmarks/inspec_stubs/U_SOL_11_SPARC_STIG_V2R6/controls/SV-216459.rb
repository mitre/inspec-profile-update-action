control 'SV-216459' do
  title 'Direct logins must not be permitted to shared, default, application, or utility accounts.'
  desc 'Shared accounts (accounts where two or more people log in with the same user identification) do not provide identification and authentication. There is no way to provide for non-repudiation or individual accountability.'
  desc 'check', 'The Audit Review profile is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Use the "auditreduce" command to check for multiple accesses to an account

# auditreduce -c lo -u [shared_user_name] | praudit -l

If users log directly into accounts, rather than using the "su" command from their own named account to access them, this is a finding. Also, ask the SA or the IAO if shared accounts are logged into directly or if users log into an individual account and switch user to the shared account.'
  desc 'fix', 'The root role is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Use the switch user ("su") command from a named account login to access shared accounts. Maintain audit trails that identify the actual user of the account name. Document requirements and procedures for users/administrators to log into their own accounts first and then switch user ("su") to the shared account.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17695r371465_chk'
  tag severity: 'medium'
  tag gid: 'V-216459'
  tag rid: 'SV-216459r603267_rule'
  tag stig_id: 'SOL-11.1-090030'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17693r371466_fix'
  tag 'documentable'
  tag legacy: ['V-47983', 'SV-60855']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
