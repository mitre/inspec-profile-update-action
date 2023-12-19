control 'SV-230217' do
  title 'If the BIG-IP appliance is being used to authenticate users for web applications, the HTTPOnly flag must be set.'
  desc 'The HttpOnly attribute directs browsers to use cookies by way of the HTTP and HTTPS protocols only, ensuring that the cookie is not available by other means, such as JavaScript function calls. This setting mitigates the risk of attack utilizing Cross Site Scripting (XSS). This vulnerability allows an attacker to impersonate any authenticated user that has visited a page with the attack deployed, allowing them to potentially allowing the user to raise their permissions level. The vulnerability can be mitigated by setting HTTPOnly on the appropriate Access Policy.'
  desc 'check', 'If the BIG-IP ASM module is not used to support user authentication, this is not applicable.

Navigate to Security >> Options >> Application Security >> Advanced Configuration >> System Variables
Verify cookie_httponly_attr is set to 1.
If the BIG-IP appliance is being used to authenticate users for web applications, the HTTPOnly flag must be set, this is a finding.'
  desc 'fix', 'Configure a policy in the BIG-IP ASM module to enable the HTTPonly flag.

Log in to the Configuration utility.

Navigate to Security >> Options >> Application Security >> Advanced Configuration >> System Variables

Create the variable cookie_httponly_attr.
Set the Parameter to 1.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-32547r561162_chk'
  tag severity: 'low'
  tag gid: 'V-230217'
  tag rid: 'SV-230217r561165_rule'
  tag stig_id: 'F5BI-DM-000290'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-32521r561163_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
