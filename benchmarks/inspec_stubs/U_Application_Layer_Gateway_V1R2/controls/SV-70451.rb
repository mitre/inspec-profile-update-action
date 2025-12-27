control 'SV-70451' do
  title 'The ALG providing user access control intermediary services must automatically terminate a user session when organization-defined conditions or trigger events that require a session disconnect occur.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

This capability is typically reserved for specific system functionality where the system owner, data owner, or organization requires additional trigger events based on specific mission needs. Conditions or trigger events requiring automatic session termination can include, for example, targeted responses to certain types of incidents and time-of-day restrictions on information system use.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services."
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG automatically terminates a user session when organization-defined conditions or trigger events that require a session disconnect occur.

If the ALG does not automatically terminate a user session when organization-defined conditions or trigger events that require a session disconnect occur, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to automatically terminate a user session when organization-defined conditions or trigger events that require a session disconnect occur.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-56747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56197'
  tag rid: 'SV-70451r1_rule'
  tag stig_id: 'SRG-NET-000517-ALG-000006'
  tag gtitle: 'SRG-NET-000517-ALG-000006'
  tag fix_id: 'F-61073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
