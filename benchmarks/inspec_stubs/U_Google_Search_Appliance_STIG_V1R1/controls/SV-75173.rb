control 'SV-75173' do
  title 'Google Search Appliances must have the capability to limit the number of failed logon attempts to 3 attempts in 15 minutes.'
  desc 'Anytime an authentication method is exposed so as to allow for the utilization of an application, there is a risk that attempts will be made to obtain unauthorized access. 

To defeat these attempts, organizations define the number of times a user account may consecutively fail a login attempt. The organization also defines the period of time in which these consecutive failed attempts may occur. 

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
  tag check_id: 'C-61667r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60721'
  tag rid: 'SV-75173r1_rule'
  tag stig_id: 'GSAP-00-000140'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-66401r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
