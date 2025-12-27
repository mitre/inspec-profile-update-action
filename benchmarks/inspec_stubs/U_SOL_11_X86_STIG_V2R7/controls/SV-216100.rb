control 'SV-216100' do
  title 'The delay between login prompts following a failed login attempt must be at least 4 seconds.'
  desc 'As an immediate return of an error message, coupled with the capability to try again, may facilitate automatic and rapid-fire brute-force password attacks by a malicious user.'
  desc 'check', 'Check the SLEEPTIME parameter in the /etc/default/login file.

# grep ^SLEEPTIME /etc/default/login

If the output is not SLEEPTIME=4 or more, this is a finding.'
  desc 'fix', 'The root role is required.

# pfedit the /etc/default/login 

Locate the line containing:

SLEEPTIME

Change the line to read:

SLEEPTIME=4'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17338r372682_chk'
  tag severity: 'medium'
  tag gid: 'V-216100'
  tag rid: 'SV-216100r603268_rule'
  tag stig_id: 'SOL-11.1-040160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17336r372683_fix'
  tag 'documentable'
  tag legacy: ['V-48043', 'SV-60915']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
