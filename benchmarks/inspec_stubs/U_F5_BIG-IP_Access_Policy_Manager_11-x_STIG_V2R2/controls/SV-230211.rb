control 'SV-230211' do
  title 'The BIG-IP APM module access policy profile must be configured to automatically terminate user sessions for users connected to virtual servers when organization-defined conditions or trigger events occur that require a session disconnect.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

This capability is typically reserved for specific system functionality where the system owner, data owner, or organization requires additional trigger events based on specific mission needs. Conditions or trigger events requiring automatic session termination can include, for example, targeted responses to certain types of incidents and time-of-day restrictions on information system use.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services."
  desc 'check', 'If the BIG-IP Am module does not provide user access control intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for organizational access.

Verify the Access Profile is configured to automatically terminate user sessions when organization-defined conditions or trigger events occur that require a session disconnect.

If the BIG-IP APM module is not configured to automatically terminate a user session when organization-defined conditions or trigger events occur that require a session disconnect, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure an access policy in the BIG-IP APM module to automatically terminate a user session when organization-defined conditions or trigger events occur that require a session disconnect.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16917r290418_chk'
  tag severity: 'medium'
  tag gid: 'V-230211'
  tag rid: 'SV-230211r856822_rule'
  tag stig_id: 'F5BI-AP-000147'
  tag gtitle: 'SRG-NET-000517-ALG-000006'
  tag fix_id: 'F-16915r290419_fix'
  tag 'documentable'
  tag legacy: ['SV-74469', 'V-60039']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
