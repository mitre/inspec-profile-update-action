control 'SV-218231' do
  title 'The system must require passwords contain at least one uppercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check the ucredit setting.
# grep ucredit /etc/pam.d/system-auth
If ucredit is not set to -1, this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so ucredit=-1

prior to the "password include system-auth-ac" line.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19706r568579_chk'
  tag severity: 'medium'
  tag gid: 'V-218231'
  tag rid: 'SV-218231r603259_rule'
  tag stig_id: 'GEN000600'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-19704r568580_fix'
  tag 'documentable'
  tag legacy: ['V-11948', 'SV-63973']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
