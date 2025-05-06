control 'SV-226463' do
  title 'The system must require passwords to contain at least one special character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check the MINSPECIAL setting.
# grep MINSPECIAL /etc/default/passwd
If the MINSPECIAL setting is less than 1, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd and set MINSPECIAL to 1.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28624r482765_chk'
  tag severity: 'medium'
  tag gid: 'V-226463'
  tag rid: 'SV-226463r603265_rule'
  tag stig_id: 'GEN000640'
  tag gtitle: 'SRG-OS-000266'
  tag fix_id: 'F-28612r482766_fix'
  tag 'documentable'
  tag legacy: ['V-11973', 'SV-27123']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
