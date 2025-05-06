control 'SV-248695' do
  title 'OL 8 passwords for new users or password changes must have a 24 hours/1 day minimum password lifetime restriction in "/etc/logins.def".'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify the operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts. 
 
Check for the value of "PASS_MIN_DAYS" in "/etc/login.defs" with the following command:  
 
$ sudo grep -i pass_min_days /etc/login.defs 
PASS_MIN_DAYS 1 
 
If the "PASS_MIN_DAYS" parameter value is not "1" or greater or is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to enforce 24 hours/1 day as the minimum password lifetime. 
 
Add the following line in "/etc/login.defs" (or modify the line to have the required value): 
 
PASS_MIN_DAYS 1'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52129r779649_chk'
  tag severity: 'medium'
  tag gid: 'V-248695'
  tag rid: 'SV-248695r779651_rule'
  tag stig_id: 'OL08-00-020190'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-52083r779650_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
