control 'SV-44800' do
  title 'The system must not have the unnecessary gopher account.'
  desc 'Accounts that provide no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for the unnecessary "gopher" accounts.

Procedure:
# grep ^gopher /etc/passwd
If this account exists, it is a finding.'
  desc 'fix', 'Remove the "gopher" account from the /etc/passwd file before connecting a system to the network.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42291r1_chk'
  tag severity: 'medium'
  tag gid: 'V-27276'
  tag rid: 'SV-44800r1_rule'
  tag stig_id: 'GEN000290-3'
  tag gtitle: 'GEN000290-3'
  tag fix_id: 'F-38248r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000012']
  tag nist: ['AC-2 j']
end
