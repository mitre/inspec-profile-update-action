control 'SV-215727' do
  title 'The BIG-IP APM module must require users to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances: 

1) When authenticators change;

2) When roles change;

3) When security categories of information systems change;

4) When the execution of privileged functions occurs;

5) After a fixed period of time; or

6) Periodically.

Within the DoD, the minimum circumstances requiring re-authentication are privilege escalation and role changes.

This requirement only applies to components where this is specific to the function of the device or has the concept of user authentication (e.g., VPN or ALG capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'If the BIG-IP APM module does not provide user authentication intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for organizational access.

Verify the Access Profile is configured to require users to re-authenticate when organization-defined circumstances or situations require re-authentication.

If the BIG-IP APM module is not configured to require users to re-authenticate when organization-defined circumstances or situations require re-authentication, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure an access policy in the BIG-IP APM module to require users to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16920r290427_chk'
  tag severity: 'medium'
  tag gid: 'V-215727'
  tag rid: 'SV-215727r557355_rule'
  tag stig_id: 'F5BI-AP-000191'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-16918r290428_fix'
  tag 'documentable'
  tag legacy: ['SV-74475', 'V-60045']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
