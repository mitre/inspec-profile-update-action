control 'SV-253066' do
  title 'TOSS must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify that TOSS enforces 24 hours/1 day as the minimum password lifetime for new user accounts.

Check for the value of "PASS_MIN_DAYS" in "/etc/login.defs" with the following command: 

$ sudo grep -i pass_min_days /etc/login.defs
PASS_MIN_DAYS 1

If the "PASS_MIN_DAYS" parameter value is not "1" or greater, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce 24 hours/1 day as the minimum password lifetime.

Add the following line in "/etc/login.defs" (or modify the line to have the required value):

PASS_MIN_DAYS 1'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56519r824868_chk'
  tag severity: 'medium'
  tag gid: 'V-253066'
  tag rid: 'SV-253066r824870_rule'
  tag stig_id: 'TOSS-04-040110'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-56469r824869_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
