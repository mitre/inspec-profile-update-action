control 'SV-230212' do
  title 'The BIG-IP APM module access policy profile must be configured to display an explicit logoff message to users, indicating the reliable termination of authenticated communications sessions when disconnecting from virtual servers.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Logoff messages for access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions, including, for example, remote logon, information systems typically send logoff messages as final messages prior to terminating sessions.

This policy only applies to ALGs (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the BIG-IP APM module does not provide user access control intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for connecting to virtual servers.

Verify the Access Profile is configured to display an explicit logoff message to users, indicating the reliable termination of authenticated communications sessions.

If the BIG-IP APM module is not configured to display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP APM module to display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-32546r831448_chk'
  tag severity: 'medium'
  tag gid: 'V-230212'
  tag rid: 'SV-230212r856824_rule'
  tag stig_id: 'F5BI-AP-000151'
  tag gtitle: 'SRG-NET-000519-ALG-000008'
  tag fix_id: 'F-16916r290422_fix'
  tag 'documentable'
  tag legacy: ['V-60041', 'SV-74471']
  tag cci: ['CCI-002364', 'CCI-000366']
  tag nist: ['AC-12 (2)', 'CM-6 b']
end
