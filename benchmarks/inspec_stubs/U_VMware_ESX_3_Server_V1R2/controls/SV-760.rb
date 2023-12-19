control 'SV-760' do
  title 'Direct logins must not be permitted to shared, default, application, or utility accounts.'
  desc 'Shared accounts (accounts where two or more people log in with the same user identification) do not provide identification and authentication.  There is no way to provide for non-repudiation or individual accountability.'
  desc 'check', 'Use the last command to check for multiple accesses to an account from different workstations/IP addresses. If users log directly onto accounts, rather than using the su command from their own named account to access them, this is a finding (such as logging directly on to Oracle). Also, ask the SA or the IAO if shared accounts are logged into directly or if users log on to an individual account and switch user to the shared account.'
  desc 'fix', 'Use the switch user (su) command from a named account login to access shared accounts. Maintain audit trails that identify the actual user of the account name. Document requirements and procedures for users/administrators to log into their own accounts first and then switch user (su) to the shared account.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27975r1_chk'
  tag severity: 'medium'
  tag gid: 'V-760'
  tag rid: 'SV-760r2_rule'
  tag stig_id: 'GEN000280'
  tag gtitle: 'GEN000280'
  tag fix_id: 'F-24339r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
