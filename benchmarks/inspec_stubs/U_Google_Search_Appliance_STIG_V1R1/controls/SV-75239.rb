control 'SV-75239' do
  title 'Google Search Appliances must enforce password minimum lifetime restrictions.'
  desc "Password minimum lifetime is defined as:  the minimum period of time, (typically in days) a user's password must be in effect before the user can change it. 

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy based intervals, however if the application allows the user to immediately and continually change their password then the password could be repeatedly changed in a short period of time so as to defeat the organizations policy regarding password reuse.

This would allow users to keep using the same password over and over again by immediately changing their password X number of times.  This would effectively negate password policy."
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "User Accounts".

Under "Other Settings" - If "Use strict password checking" is checked, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "User Accounts".

Under "Other Settings" - Enable option "Use strict password checking".

Click Save.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60787'
  tag rid: 'SV-75239r1_rule'
  tag stig_id: 'GSAP-00-000570'
  tag gtitle: 'SRG-APP-000173'
  tag fix_id: 'F-66469r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
