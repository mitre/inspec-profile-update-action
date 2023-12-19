control 'SV-86107' do
  title 'The CA API Gateway providing user access control intermediary services must provide a logoff capability for user-initiated communications sessions.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker.

However, for some types of interactive sessions, including, for example, remote logon, information systems typically send logoff messages as final messages prior to terminating sessions.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.

The CA API Gateway must register, protect, and expose the API responsible for logoff capability. Policy can then be configured to allow the Logoff Registered Service to be initiated through the application requiring the user logoff capability.'
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Verify that all services/applications requiring user-initiated logoff are registered on the Gateway and that the Logoff API is included and exposed to the users requiring user-initiated logoff capability. 

If not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and register the Logoff APIs as Registered Services. 

Assign the proper policy to the Registered Service in accordance with organizational requirements for securing/protecting Registered Services/APIs. 

For more details, refer to the "Layer 7 Policy Authoring User Manual".

Additionally, update all applications developed within the organization to call the newly added Registered Service in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71483'
  tag rid: 'SV-86107r1_rule'
  tag stig_id: 'CAGW-GW-000960'
  tag gtitle: 'SRG-NET-000518-ALG-000007'
  tag fix_id: 'F-77803r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
