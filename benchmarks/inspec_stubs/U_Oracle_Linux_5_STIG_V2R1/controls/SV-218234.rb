control 'SV-218234' do
  title 'The system must require passwords contain at least one numeric character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check the dcredit setting.

Procedure:
Check the password dcredit option
# grep pam_cracklib.so /etc/pam.d/system-auth

Confirm the dcredit option is set to -1 as in the example:

password required pam_cracklib.so dcredit=-1

There may be other options on the line. If no such line is found, or the dcredit option is not -1 this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so dcredit=-1

prior to the "password include system-auth-ac" line.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19709r568663_chk'
  tag severity: 'medium'
  tag gid: 'V-218234'
  tag rid: 'SV-218234r603259_rule'
  tag stig_id: 'GEN000620'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-19707r568664_fix'
  tag 'documentable'
  tag legacy: ['V-11972', 'SV-64071']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
