control 'SV-86105' do
  title 'The CA API Gateway providing user access control intermediary services must automatically terminate a user session when organization-defined conditions or trigger events that require a session disconnect occur.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session, except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

This capability is typically reserved for specific system functionality where the system owner, data owner, or organization requires additional trigger events based on specific mission needs. Conditions or trigger events requiring automatic session termination can include, for example, targeted responses to certain types of incidents and time-of-day restrictions on information system use.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.

The CA API Gateway must place restrictions on Registered Services, such as time/day restrictions, and generate targeted responses to certain types of incidents based on organizational requirements for disconnecting sessions."
  desc 'check', "Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring organization-defined conditions for session disconnects. 

Verify the Registered Services' policies are configured in accordance with organizational requirements for time-of-day restrictions or other incidents causing the need for a session disconnect and targeted responses. 

If they are not, this is a finding."
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services that did not meet the organization-defined conditions for session disconnects. 

Configure the policies in accordance with organizational requirements for time-of-day restriction or other events requiring session disconnects and targeted responses. 

For more details, refer to the "CA API Management Documentation Wiki" at https://wiki.ca.com/display/GATEWAY90/CA+API+Gateway+Home.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71481'
  tag rid: 'SV-86105r1_rule'
  tag stig_id: 'CAGW-GW-000950'
  tag gtitle: 'SRG-NET-000517-ALG-000006'
  tag fix_id: 'F-77801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
