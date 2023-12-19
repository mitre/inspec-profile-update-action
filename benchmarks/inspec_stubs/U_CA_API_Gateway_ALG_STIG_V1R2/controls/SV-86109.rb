control 'SV-86109' do
  title 'The CA API Gateway providing user access control intermediary services must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Logoff messages for access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, remote logon, information systems typically send logoff messages as final messages prior to terminating sessions.

This policy only applies to ALGs (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.

The CA API Gateway must return a custom template response upon calling a service. All developed applications protected by the CA API Gateway must be set up to call a CA API Gateway Service, which upon selecting "logoff" within the application, terminates the authenticated session and displays an explicit logoff message.'
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Verify that a Registered Service is present for displaying an explicit logoff message using a "Return Template Response" Assertion. 

If the Registered Service is not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and create a Registered Service that includes a "Return Template Response" Assertion in accordance with organizational requirements for an explicit logoff message. 

For more details, refer to the "CA API Management Documentation Wiki" at https://wiki.ca.com/display/GATEWAY90/CA+API+Gateway+Home.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71485'
  tag rid: 'SV-86109r1_rule'
  tag stig_id: 'CAGW-GW-000970'
  tag gtitle: 'SRG-NET-000519-ALG-000008'
  tag fix_id: 'F-77805r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
