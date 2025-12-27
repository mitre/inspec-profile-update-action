control 'SV-12474' do
  title 'The system must require that passwords contain at least one special character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Verify the system requires passwords contain at least one special character.'
  desc 'fix', 'Configure the system to require passwords contain at least one special character.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28040r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11973'
  tag rid: 'SV-12474r2_rule'
  tag stig_id: 'GEN000640'
  tag gtitle: 'GEN000640'
  tag fix_id: 'F-24388r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
