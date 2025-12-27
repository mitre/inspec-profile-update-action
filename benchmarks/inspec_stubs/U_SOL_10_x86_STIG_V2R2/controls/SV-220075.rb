control 'SV-220075' do
  title 'The delay between login prompts following a failed login attempt must be at least 4 seconds.'
  desc 'Enforcing a delay between successive failed login attempts increases protection against automated password guessing attacks.'
  desc 'check', 'Check the SLEEPTIME parameter in the /etc/default/login file.

# grep SLEEPTIME /etc/default/login

If SLEEPTIME is not listed, commented out, or less than 4, this is a finding.'
  desc 'fix', 'Edit the /etc/default/login file and set SLEEPTIME to 4.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21784r488279_chk'
  tag severity: 'medium'
  tag gid: 'V-220075'
  tag rid: 'SV-220075r603266_rule'
  tag stig_id: 'GEN000480'
  tag gtitle: 'SRG-OS-000329'
  tag fix_id: 'F-21783r488280_fix'
  tag 'documentable'
  tag legacy: ['V-768', 'SV-27094']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
