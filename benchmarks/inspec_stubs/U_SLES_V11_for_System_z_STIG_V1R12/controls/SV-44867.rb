control 'SV-44867' do
  title 'The system must require passwords contain at least one lowercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check /etc/pam.d/common-password for lcredit setting.

Procedure:
Check the password lcredit option
# grep pam_cracklib.so /etc/pam.d/common-password

Confirm the lcredit option is set to -1 as in the example:

password required pam_cracklib.so lcredit=-1

There may be other options on the line. If no such line is found, or the lcredit is not -1 this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/common-password" to include the line:

password required pam_cracklib.so lcredit=-1'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42329r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22305'
  tag rid: 'SV-44867r1_rule'
  tag stig_id: 'GEN000610'
  tag gtitle: 'GEN000610'
  tag fix_id: 'F-38300r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
