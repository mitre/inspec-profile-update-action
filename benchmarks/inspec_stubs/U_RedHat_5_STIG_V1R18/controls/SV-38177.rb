control 'SV-38177' do
  title 'The system must not have the unnecessary "games" account.'
  desc 'Accounts that provide no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for the unnecessary "games" accounts.

Procedure:
# grep ^games /etc/passwd
If this account exists, it is a finding.'
  desc 'fix', 'Remove the "games" account.

Procedure:
# userdel games'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37561r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29376'
  tag rid: 'SV-38177r1_rule'
  tag stig_id: 'GEN000290-1'
  tag gtitle: 'GEN000290-1'
  tag fix_id: 'F-32805r2_fix'
  tag 'documentable'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000012']
  tag nist: ['AC-2 j']
end
