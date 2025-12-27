control 'SV-44866' do
  title 'The system must require passwords contain at least one uppercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check the ucredit setting.
# grep ucredit /etc/pam.d/common-password-pc
If ucredit is not set to -1, this is a finding.'
  desc 'fix', 'Edit /etc/pam.d/common-password-pc and set ucredit to -1.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42328r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11948'
  tag rid: 'SV-44866r1_rule'
  tag stig_id: 'GEN000600'
  tag gtitle: 'GEN000600'
  tag fix_id: 'F-38299r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
