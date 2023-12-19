control 'SV-226462' do
  title 'The system must require passwords to contain at least one numeric character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Check the MINDIGIT setting.
# grep MINDIGIT /etc/default/passwd
If the MINDIGIT setting is less than 1, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd and set the MINDIGIT setting to 1.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28623r482762_chk'
  tag severity: 'medium'
  tag gid: 'V-226462'
  tag rid: 'SV-226462r603265_rule'
  tag stig_id: 'GEN000620'
  tag gtitle: 'SRG-OS-000071'
  tag fix_id: 'F-28611r482763_fix'
  tag 'documentable'
  tag legacy: ['V-11972', 'SV-27119']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
