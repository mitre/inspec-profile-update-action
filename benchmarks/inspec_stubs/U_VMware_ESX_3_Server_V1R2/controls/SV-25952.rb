control 'SV-25952' do
  title 'The system must require passwords contain at least one lowercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Determine if the system requires at least one lowercase alphabetic character for passwords.  If it does not, this is a finding.'
  desc 'fix', 'Configure the system to require at least one lowercase alphabetic character for passwords.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29096r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22305'
  tag rid: 'SV-25952r1_rule'
  tag stig_id: 'GEN000610'
  tag gtitle: 'GEN000610'
  tag fix_id: 'F-26095r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
