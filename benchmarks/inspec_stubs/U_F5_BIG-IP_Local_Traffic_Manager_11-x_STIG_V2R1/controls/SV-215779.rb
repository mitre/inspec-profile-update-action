control 'SV-215779' do
  title 'The BIG-IP Core implementation must be configured to require users to re-authenticate to virtual servers when organization-defined circumstances or situations require re-authentication.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances: 

1) When authenticators change;
2) When roles change;
3) When security categories of information systems change;
4) When the execution of privileged functions occurs;
5) After a fixed period of time; and
6) Periodically.

Within the DoD, the minimum circumstances requiring re-authentication are privilege escalation and role changes.

This requirement only applies to components where this is specific to the function of the device or has the concept of user authentication (e.g., VPN or ALG capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to require users to re-authenticate when required by organization-defined circumstances or situations.

Navigate to the BIG-IP System manager>>Local Traffic>>Virtual Servers>>Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section that "Access Policy" has been set to use an APM access policy that requires users to re-authenticate to virtual servers when organization-defined circumstances or situations require re-authentication.

If the BIG-IP Core is not configured to require users to re-authenticate when organization-defined circumstances or situations require re-authentication, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to require multifactor authentication for remote access to require users to re-authenticate when required by organization-defined circumstances or situations.

Apply APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to require users to re-authenticate to virtual servers when organization-defined circumstances or situations require re-authentication.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16971r291150_chk'
  tag severity: 'medium'
  tag gid: 'V-215779'
  tag rid: 'SV-215779r557356_rule'
  tag stig_id: 'F5BI-LT-000191'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-16969r291151_fix'
  tag 'documentable'
  tag legacy: ['SV-74769', 'V-60339']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
