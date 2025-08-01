control 'SV-227587' do
  title 'The system must require passwords to contain at least one uppercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check the MINUPPER setting.
# egrep MINUPPER /etc/default/passwd
If MINUPPER is not set to 1 or more, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd and set the MINUPPER setting to at least 1.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29749r488309_chk'
  tag severity: 'medium'
  tag gid: 'V-227587'
  tag rid: 'SV-227587r603266_rule'
  tag stig_id: 'GEN000600'
  tag gtitle: 'SRG-OS-000069'
  tag fix_id: 'F-29737r488310_fix'
  tag 'documentable'
  tag legacy: ['V-11948', 'SV-27115']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
