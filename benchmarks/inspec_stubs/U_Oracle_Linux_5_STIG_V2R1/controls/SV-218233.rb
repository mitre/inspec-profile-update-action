control 'SV-218233' do
  title 'The system must require passwords contain at least one lowercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check /etc/pam.d/system-auth for lcredit setting.

Procedure:
Check the password lcredit option
# grep pam_cracklib.so /etc/pam.d/system-auth

Confirm the lcredit option is set to -1 as in the example:

password required pam_cracklib.so lcredit=-1

There may be other options on the line. 

If no such line is found, or the lcredit is not -1 this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so lcredit=-1

prior to the "password include system-auth-ac" line.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19708r568660_chk'
  tag severity: 'medium'
  tag gid: 'V-218233'
  tag rid: 'SV-218233r603259_rule'
  tag stig_id: 'GEN000610'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-19706r568661_fix'
  tag 'documentable'
  tag legacy: ['V-22305', 'SV-64065']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
