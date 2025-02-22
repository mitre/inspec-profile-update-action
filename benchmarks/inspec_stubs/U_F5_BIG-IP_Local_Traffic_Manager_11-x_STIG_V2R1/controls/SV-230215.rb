control 'SV-230215' do
  title 'The BIG-IP Core must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions when providing access to virtual servers.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Logoff messages for access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, remote logon, information systems typically send logoff messages as final messages prior to terminating sessions.

This policy only applies to ALGs (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services for virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions when providing access to virtual servers.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an APM access policy that displays an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

If the BIG-IP Core is not configured to display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

Apply APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions when providing access to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16963r291126_chk'
  tag severity: 'medium'
  tag gid: 'V-230215'
  tag rid: 'SV-230215r561160_rule'
  tag stig_id: 'F5BI-LT-000151'
  tag gtitle: 'SRG-NET-000519-ALG-000008'
  tag fix_id: 'F-16961r291127_fix'
  tag 'documentable'
  tag legacy: ['V-60323', 'SV-74753']
  tag cci: ['CCI-002364', 'CCI-000366']
  tag nist: ['AC-12 (2)', 'CM-6 b']
end
