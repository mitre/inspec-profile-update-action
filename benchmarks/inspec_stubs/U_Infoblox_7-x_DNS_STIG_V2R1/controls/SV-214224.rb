control 'SV-214224' do
  title 'Infoblox systems must be configured with current DoD password restrictions.'
  desc 'The Infoblox systems must be configured to meet current DoD password policy when using the Infoblox Local User Database as the authentication source.'
  desc 'check', 'Navigate to Administration >> Administrators >> Authentication Policy.

If the only authentication type under "Authenticate users in this order" is "Local User Database", perform the following additional validation:

Navigate to Grid >> Grid Manager >> Grid Properties >> Password tab.

Verify the settings are configured in accordance with current DoD Policy.

If the Infoblox system is configured to utilize a remote authentication system (Active Directory, RADIUS, TACACS+, or LDAP) which enforces policy, or the password settings meet current guidance this is not a finding.'
  desc 'fix', 'Navigate to Grid >> Grid Manager >> Grid Properties >> Password tab.

Configure the system with appropriate values for password length, complexity, and expiration requirements.'
  impact 0.7
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15439r295935_chk'
  tag severity: 'high'
  tag gid: 'V-214224'
  tag rid: 'SV-214224r612370_rule'
  tag stig_id: 'IDNS-7X-000990'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-15437r295936_fix'
  tag 'documentable'
  tag legacy: ['SV-83113', 'V-68623']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
