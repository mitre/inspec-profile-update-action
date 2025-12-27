control 'SV-233883' do
  title 'Infoblox systems must enforce current DoD password restrictions.'
  desc 'The Infoblox systems must be configured to meet current DoD password policy when using the Infoblox Local User Database as the authentication source.'
  desc 'check', '1. Navigate to Administration >> Administrators >> Authentication Policy. 
2. If the only authentication type under "Authenticate users in this order" is "Local User Database", perform the following additional validation: 
3. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration.  
4. Select the "Password" tab. 
5. Verify the settings are configured in accordance with current DoD Policy.  

If the Infoblox system is configured to use a remote authentication system (Active Directory, RADIUS, TACACS+, or LDAP) that enforces password policy, or the password settings meet current guidance, this is not a finding.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration.  
2. Select the "Password" tab. 
3. Configure the system with appropriate values for password length, complexity, and expiration requirements.'
  impact 0.7
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37068r611169_chk'
  tag severity: 'high'
  tag gid: 'V-233883'
  tag rid: 'SV-233883r621666_rule'
  tag stig_id: 'IDNS-8X-400025'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-37033r611170_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
