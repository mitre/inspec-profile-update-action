control 'SV-215727' do
  title "The BIG-IP APM module must require users to reauthenticate when the user's role or information authorizations are changed."
  desc 'Without reauthentication, users may access resources or perform tasks for which authorization has been removed.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations. Within the DOD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.

This requirement only applies to components where this is specific to the function of the device or has the concept of user authentication (e.g., VPN or ALG capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', %q(If the BIG-IP APM module does not provide user authentication intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for each Access Profile used for organizational access.

If the BIG-IP APM module is not configured or process is not documented to require users to reauthenticate when the user's role or information authorizations are changed, this is a finding.)
  desc 'fix', "Configure an access policy in the BIG-IP APM module to require users to reauthenticate when the user's role or information authorizations are changed.

This will also require the administrator to force reauthentication when changes occur that the system cannot automatically detect. Update administrator training and the site's SSP to document this process."
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16920r939136_chk'
  tag severity: 'medium'
  tag gid: 'V-215727'
  tag rid: 'SV-215727r939138_rule'
  tag stig_id: 'F5BI-AP-000191'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-16918r939137_fix'
  tag 'documentable'
  tag legacy: ['V-60045', 'SV-74475']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
