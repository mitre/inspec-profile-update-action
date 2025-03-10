control 'SV-44838' do
  title 'The delay between login prompts following a failed login attempt must be at least 4 seconds.'
  desc 'Enforcing a delay between successive failed login attempts increases protection against automated password guessing attacks.'
  desc 'check', 'Check the value of the FAIL_DELAY variable and the ability to use it

Procedure:.
# grep FAIL_DELAY /etc/login.defs 
If the value does not exist, or is less than 4, this is a finding.

Check for the use of pam_faildelay.
# grep pam_faildelay /etc/pam.d/common-auth*
If the pam_faildelay.so module is not listed, this is a finding.'
  desc 'fix', 'Add the pam_faildelay module and set the FAIL_DELAY variable.

Procedure:
Edit /etc/login.defs and set the value of the FAIL_DELAY variable to 4 or more.

Edit /etc/pam.d/common-auth and add a pam_faildelay entry if one does not exist, such as:
auth optional pam_faildelay.so'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42309r1_chk'
  tag severity: 'medium'
  tag gid: 'V-768'
  tag rid: 'SV-44838r1_rule'
  tag stig_id: 'GEN000480'
  tag gtitle: 'GEN000480'
  tag fix_id: 'F-38275r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
