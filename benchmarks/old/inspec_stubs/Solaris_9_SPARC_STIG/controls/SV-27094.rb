control 'SV-27094' do
  title 'The delay between login prompts following a failed login attempt must be at least 4 seconds.'
  desc 'Enforcing a delay between successive failed login attempts increases protection against automated password guessing attacks.'
  desc 'fix', 'Edit the /etc/default/login file and set SLEEPTIME to 4.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-768'
  tag rid: 'SV-27094r1_rule'
  tag stig_id: 'GEN000480'
  tag gtitle: 'GEN000480'
  tag fix_id: 'F-24360r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
