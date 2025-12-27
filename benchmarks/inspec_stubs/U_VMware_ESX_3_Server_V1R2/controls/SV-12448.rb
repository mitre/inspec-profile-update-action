control 'SV-12448' do
  title 'The system must require that passwords contain a minimum of 14 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
  desc 'check', 'Check the system minimum password length setting.  If the setting is not 14 or greater, this is a finding.'
  desc 'fix', 'Set the system minimum password length setting to 14 or greater.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28025r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11947'
  tag rid: 'SV-12448r2_rule'
  tag stig_id: 'GEN000580'
  tag gtitle: 'GEN000580'
  tag fix_id: 'F-24372r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
