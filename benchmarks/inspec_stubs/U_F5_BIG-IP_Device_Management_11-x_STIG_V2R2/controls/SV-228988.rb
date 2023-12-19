control 'SV-228988' do
  title 'The BIG-IP appliance must be configured to uniquely identify and authenticate organizational administrators (or processes acting on behalf of organizational administrators).'
  desc 'To assure accountability and prevent unauthenticated access, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that uniquely identifies and authenticates organizational administrators. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that uniquely identifies and authenticates organizational administrators.

If the BIG-IP appliance is not configured to use a properly configured authentication server that uniquely identifies and authenticates organizational administrators, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server that uniquely identifies and authenticates organizational administrators.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31303r518009_chk'
  tag severity: 'high'
  tag gid: 'V-228988'
  tag rid: 'SV-228988r879887_rule'
  tag stig_id: 'F5BI-DM-000095'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31280r518010_fix'
  tag 'documentable'
  tag legacy: ['SV-74573', 'V-60143']
  tag cci: ['CCI-000366', 'CCI-000764']
  tag nist: ['CM-6 b', 'IA-2']
end
