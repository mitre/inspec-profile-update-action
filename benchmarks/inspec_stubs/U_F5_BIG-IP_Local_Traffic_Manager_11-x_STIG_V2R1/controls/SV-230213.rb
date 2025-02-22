control 'SV-230213' do
  title 'The BIG-IP Core implementation must be configured to initiate a session lock after a 15-minute period of inactivity when users are connected to virtual servers.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their session prior to vacating the vicinity, network elements need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services."
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP Core initiates a session lock after a 15-minute period of inactivity.

Select a profile for user sessions.

Verify "Keep Alive Interval" under "Settings" section is set to "Specify" 900.

Verify the BIG-IP LTM is configured to use the Protocol Profile.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select appropriate virtual server.

Verify "Protocol Profile (Client)" is set to a profile that limits session timeout.

If the BIG-IP Core does not initiate a session lock after a 15-minute period of inactivity, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core to initiate a session lock after a 15-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16960r291117_chk'
  tag severity: 'medium'
  tag gid: 'V-230213'
  tag rid: 'SV-230213r561158_rule'
  tag stig_id: 'F5BI-LT-000141'
  tag gtitle: 'SRG-NET-000514-ALG-000514'
  tag fix_id: 'F-16958r291118_fix'
  tag 'documentable'
  tag legacy: ['V-60317', 'SV-74747']
  tag cci: ['CCI-000057', 'CCI-000366']
  tag nist: ['AC-11 a', 'CM-6 b']
end
