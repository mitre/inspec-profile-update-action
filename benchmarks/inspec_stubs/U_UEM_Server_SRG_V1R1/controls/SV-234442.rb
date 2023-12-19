control 'SV-234442' do
  title 'The UEM server must automatically terminate a user session after an organization-defined period of user inactivity.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific application system functionality where the system owner, data owner, or organization requires additional assurance. Based upon requirements and events specified by the data or application owner, the application developer must incorporate logic into the application that will provide a control mechanism that disconnects users upon the defined event trigger. The methods for incorporating this requirement will be determined and specified on a case-by-case basis during the application design and development stages. 

Satisfies:FMT_SMF.1.1(2) b 
Reference:PP-MDM-431014"
  desc 'check', 'Verify the UEM server automatically terminates a user session after an organization-defined period of user inactivity.

If the UEM server does not automatically terminate a user session after an organization-defined period of user inactivity, this is a finding.'
  desc 'fix', 'Configure the UEM server to automatically terminate a user session after an organization-defined period of user inactivity.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37627r614336_chk'
  tag severity: 'medium'
  tag gid: 'V-234442'
  tag rid: 'SV-234442r617355_rule'
  tag stig_id: 'SRG-APP-000295-UEM-000169'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-37592r614337_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
