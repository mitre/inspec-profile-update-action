control 'SV-44876' do
  title 'The system must require passwords contain at least one special character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check the ocredit setting.

Procedure:
Check the password ocredit option
# grep pam_cracklib.so /etc/pam.d/common-password-pc

Confirm the ocredit option is set to -1 as in the example:

password required pam_cracklib.so ocredit=-1

There may be other options on the line. If no such line is found, or the ocredit is not -1 this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/common-password-pc" to include the line:

password required pam_cracklib.so ocredit=-1'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42331r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11973'
  tag rid: 'SV-44876r1_rule'
  tag stig_id: 'GEN000640'
  tag gtitle: 'GEN000640'
  tag fix_id: 'F-38309r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
