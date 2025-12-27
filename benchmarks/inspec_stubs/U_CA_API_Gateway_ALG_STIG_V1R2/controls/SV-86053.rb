control 'SV-86053' do
  title 'The CA API Gateway providing user authentication intermediary services must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances: 

1) When authenticators change
2) When roles change
3) When security categories of information systems change
4) When the execution of privileged functions occurs
5) After a fixed period of time
6) Periodically

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.

This requirement only applies to components where this is specific to the function of the device or has the concept of user authentication (e.g., VPN or ALG capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management). 

The CA API Gateway must include in policies requiring users to reauthenticate logic to check the session token used by the client for expiration on each request and check if the session has expired, and if so, redirect them to the authentication provider.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and verify the Registered Services installed on the Gateway that require re-authentication mechanisms are configured to check for session token expiration. 

If they are not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and update the Registered Services installed on the CA API Gateway that require reauthentication mechanisms with logic to check for session token expiration. 

For more details, refer to the “CA API Management Documentation Wiki" at https://wiki.ca.com/display/GATEWAY90/CA+API+Gateway+Home.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71819r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71429'
  tag rid: 'SV-86053r1_rule'
  tag stig_id: 'CAGW-GW-000600'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-77747r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
