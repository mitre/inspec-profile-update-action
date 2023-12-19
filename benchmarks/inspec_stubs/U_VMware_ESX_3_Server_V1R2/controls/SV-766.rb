control 'SV-766' do
  title 'The system must disable accounts after three consecutive unsuccessful login attempts.'
  desc 'Disabling accounts after a limited number of unsuccessful login attempts improves protection against password guessing attacks.'
  desc 'check', 'Attempt to log on with a valid user id and incorrect password three times. If the system does not lock the account, requiring an SA to unlock it, this is a finding.'
  desc 'fix', 'Configure the system to lock accounts after three unsuccessful login attempts.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27998r1_chk'
  tag severity: 'medium'
  tag gid: 'V-766'
  tag rid: 'SV-766r2_rule'
  tag stig_id: 'GEN000460'
  tag gtitle: 'GEN000460'
  tag fix_id: 'F-24355r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
