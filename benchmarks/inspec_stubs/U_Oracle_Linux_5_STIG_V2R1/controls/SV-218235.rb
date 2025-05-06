control 'SV-218235' do
  title 'The system must require passwords contain at least one special character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check the ocredit setting.

Procedure:
Check the password ocredit option
# grep pam_cracklib.so /etc/pam.d/system-auth

Confirm the ocredit option is set to -1 as in the example:

password required pam_cracklib.so ocredit=-1

There may be other options on the line. If no such line is found, or the ocredit is not -1 this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so ocredit=-1

prior to the "password include system-auth-ac" line.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19710r568666_chk'
  tag severity: 'medium'
  tag gid: 'V-218235'
  tag rid: 'SV-218235r603259_rule'
  tag stig_id: 'GEN000640'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-19708r568667_fix'
  tag 'documentable'
  tag legacy: ['V-11973', 'SV-64075']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
