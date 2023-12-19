control 'SV-230214' do
  title 'The BIG-IP Core implementation must automatically terminate a user session for a user connected to virtual servers when organization-defined conditions or trigger events occur that require a session disconnect.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

This capability is typically reserved for specific system functionality where the system owner, data owner, or organization requires additional trigger events based on specific mission needs. Conditions or trigger events requiring automatic session termination can include, for example, targeted responses to certain types of incidents and time-of-day restrictions on information system use.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services."
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services for virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to automatically terminate user sessions for users connected to virtual servers when organization-defined conditions or trigger events occur that require a session disconnect.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify. 

Verify under "Access Policy" section that "Access Policy" has been set to use an APM access policy to automatically terminate a user session when organization-defined conditions or trigger events occur that require a session disconnect.

If the BIG-IP Core is not configured to automatically terminate a user session when organization-defined conditions or trigger events occur that require a session disconnect, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to automatically terminate a user session when organization-defined conditions or trigger events occur that require a session disconnect.

Apply APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to automatically terminate a user session for a user connected to virtual servers when organization-defined conditions or trigger events occur that require a session disconnect.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16962r291123_chk'
  tag severity: 'medium'
  tag gid: 'V-230214'
  tag rid: 'SV-230214r561159_rule'
  tag stig_id: 'F5BI-LT-000147'
  tag gtitle: 'SRG-NET-000517-ALG-000006'
  tag fix_id: 'F-16960r291124_fix'
  tag 'documentable'
  tag legacy: ['SV-74751', 'V-60321']
  tag cci: ['CCI-000366', 'CCI-002361']
  tag nist: ['CM-6 b', 'AC-12']
end
