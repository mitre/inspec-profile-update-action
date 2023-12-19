control 'SV-768' do
  title 'The delay between login prompts following a failed login attempt must be at least 4 seconds.'
  desc 'Enforcing a delay between successive failed login attempts increases protection against automated password guessing attacks.'
  desc 'check', 'Attempt to log on to the system with an invalid user account name and an incorrect password.  If the system does not pause for at least 4 seconds before displaying another logon prompt, this is a finding.'
  desc 'fix', 'Configure the system to delay at least 4 seconds between login prompts following a failed login attempt.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-768'
  tag rid: 'SV-768r2_rule'
  tag stig_id: 'GEN000480'
  tag gtitle: 'GEN000480'
  tag fix_id: 'F-24359r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
