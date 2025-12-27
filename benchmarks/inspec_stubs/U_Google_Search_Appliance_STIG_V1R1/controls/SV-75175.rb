control 'SV-75175' do
  title 'The Google Search Appliance must enforce the 15 minute time period during which the limit of consecutive invalid access attempts by a user is counted.'
  desc 'Anytime an authentication method is exposed, so as to allow for the utilization of an application, there is a risk that attempts will be made to obtain unauthorized access. 

To aid in defeating these attempts, organizations define the number of times that a user account may consecutively fail a login attempt. The organization also defines the period of time in which these consecutive failed attempts may occur. 

By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
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
  tag check_id: 'C-61669r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60723'
  tag rid: 'SV-75175r1_rule'
  tag stig_id: 'GSAP-00-000145'
  tag gtitle: 'SRG-APP-000066'
  tag fix_id: 'F-66403r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001452']
  tag nist: ['AC-7 a']
end
