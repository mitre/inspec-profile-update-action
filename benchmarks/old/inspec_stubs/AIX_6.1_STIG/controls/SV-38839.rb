control 'SV-38839' do
  title 'The delay between login prompts following a failed login attempt must be at least 4 seconds.'
  desc 'Enforcing a delay between successive failed login attempts increases protection against automated password guessing attacks.'
  desc 'check', 'Check the logindelay parameter.
# more /etc/security/login.cfg 
OR
#grep logindelay /etc/security/login.cfg | grep -v \\*

Verify the value of the logindelay variable is 4 or more in each stanza.   If the value of logindelay is not 4 or more, this is a finding.'
  desc 'fix', 'Use vi  or the chsec command to change the login delay time period.

#chsec -f /etc/security/login.cfg -s default -a logindelay=4   

OR

# vi /etc/security/login.cfg 
Add logindelay = 4 to the default stanza.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37832r1_chk'
  tag severity: 'medium'
  tag gid: 'V-768'
  tag rid: 'SV-38839r1_rule'
  tag stig_id: 'GEN000480'
  tag gtitle: 'GEN000480'
  tag fix_id: 'F-33091r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
