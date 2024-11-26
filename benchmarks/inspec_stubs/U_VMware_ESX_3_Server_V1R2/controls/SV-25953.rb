control 'SV-25953' do
  title 'The system must require at least four characters be changed between the old and new passwords during a password change.'
  desc 'To ensure password changes are effective in their goals, the system must ensure old and new passwords have significant differences. Without significant changes, new passwords may be easily guessed based on the value of a previously compromised password.'
  desc 'check', 'Consult vendor documentation for the configuration setting that controls the minimum number of changed characters required during a password change. If the configured number is less than 4, this is a finding.'
  desc 'fix', 'Consult vendor documentation for the configuration setting that controls the minimum number of changed characters required during a password change. Change the setting to 4.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22306'
  tag rid: 'SV-25953r1_rule'
  tag stig_id: 'GEN000750'
  tag gtitle: 'GEN000750'
  tag fix_id: 'F-27391r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
