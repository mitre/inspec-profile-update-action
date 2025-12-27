control 'SV-217405' do
  title 'The BIG-IP appliance must only transmit encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that transmits only encrypted representations of passwords. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that only transmits encrypted representations of passwords. 

If the BIG-IP appliance is not configured to use a properly configured authentication server that only transmits encrypted representations of passwords, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance or its associated authentication server to transmit only encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18630r290769_chk'
  tag severity: 'medium'
  tag gid: 'V-217405'
  tag rid: 'SV-217405r879609_rule'
  tag stig_id: 'F5BI-DM-000123'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-18628r290770_fix'
  tag 'documentable'
  tag legacy: ['SV-74589', 'V-60159']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
