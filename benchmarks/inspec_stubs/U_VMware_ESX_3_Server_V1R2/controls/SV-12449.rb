control 'SV-12449' do
  title 'The system must require that passwords contain at least one uppercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'Determine if at least 1 lowercase letter is required for passwords.

If the settings do not enforce at least 1 lower case letter, this is a finding.'
  desc 'fix', 'Configure the system to require at least 1 lowercase letter for passwords.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7925r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11948'
  tag rid: 'SV-12449r2_rule'
  tag stig_id: 'GEN000600'
  tag gtitle: 'GEN000600'
  tag fix_id: 'F-11219r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
