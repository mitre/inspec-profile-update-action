control 'SV-37213' do
  title 'The delay between login prompts following a failed login attempt must be at least 4 seconds.'
  desc 'Enforcing a delay between successive failed login attempts increases protection against automated password guessing attacks.'
  desc 'check', 'Check the value of the FAIL_DELAY variable and the ability to use it.

Procedure:
# grep FAIL_DELAY /etc/login.defs 
If the value does not exist, or is less than 4, this is a finding.

Check for the use of pam_faildelay.
# grep pam_faildelay /etc/pam.d/system-auth*
If pam_faildelay.so module is not present, this is a finding.

If pam_faildelay is present only in /etc/pam.d/system-auth-ac:
ensure that /etc/pam.d/system-auth includes /etc/pam.d/system-auth-ac.
#grep system-auth-ac /etc/pam.d/system-auth

This should return:
auth include system-auth-ac
account include system-auth-ac
password include system-auth-ac
session include system-auth-ac

/etc/pam.d/system-auth-ac should only be included by /etc/pam.d/system-auth. All other pam files should include /etc/pam.d/system-auth. 

If pam_faildelay is not defined in /etc/pam.d/system-auth either directly or through inclusion of system-auth-ac, this is a finding.'
  desc 'fix', 'Add the pam_faildelay module and set the FAIL_DELAY variable.

Procedure:

Edit /etc/login.defs and set the value of the FAIL_DELAY variable to 4 or more.

The default link /etc/pam.d/system-auth points to /etc/pam.d/system-auth-ac which is the file maintained by the authconfig utility. In order to add pam options other than those available via the utility create or modify /etc/pam.d/system-auth-local with the options and including system-auth-ac. For example:

auth required pam_access.so
auth optional pam_faildelay.so delay=4000000
auth include system-auth-ac
account include system-auth-ac
password include system-auth-ac
session include system-auth-ac

Once system-auth-local is written ensure the /etc/pam.d/system-auth points to system-auth-local. This is necessary because authconfig writes directly to system-auth-ac so any manual changes made will be lost if authconfig is run.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35903r2_chk'
  tag severity: 'medium'
  tag gid: 'V-768'
  tag rid: 'SV-37213r2_rule'
  tag stig_id: 'GEN000480'
  tag gtitle: 'GEN000480'
  tag fix_id: 'F-31161r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
