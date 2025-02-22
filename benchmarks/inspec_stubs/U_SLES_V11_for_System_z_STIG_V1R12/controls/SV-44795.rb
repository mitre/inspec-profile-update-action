control 'SV-44795' do
  title 'The system must not have the unnecessary games account.'
  desc 'Accounts that provide no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for the unnecessary "games" accounts.

Procedure:
# grep ^games /etc/passwd
If this account exists, it is a finding.'
  desc 'fix', 'Remove the "games" account from the /etc/passwd file before connecting a system to the network.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42289r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29376'
  tag rid: 'SV-44795r1_rule'
  tag stig_id: 'GEN000290-1'
  tag gtitle: 'GEN000290-1'
  tag fix_id: 'F-38244r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000012']
  tag nist: ['AC-2 j']
end
