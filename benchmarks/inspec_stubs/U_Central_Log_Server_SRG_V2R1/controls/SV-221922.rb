control 'SV-221922' do
  title 'The Central Log Server must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific application system functionality where the system owner, data owner, or organization requires additional assurance. Based upon requirements and events specified by the data or application owner, the application developer must incorporate logic into the application that will provide a control mechanism that disconnects users upon the defined event trigger. The methods for incorporating this requirement will be determined and specified on a case by case basis during the application design and development stages."
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to automatically terminate a user session after organization-defined conditions or trigger events.

If the Central Log Server is not configured to automatically terminate a user session after organization-defined conditions or trigger events, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to automatically terminate a user session after organization-defined conditions or trigger events.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23637r420108_chk'
  tag severity: 'medium'
  tag gid: 'V-221922'
  tag rid: 'SV-221922r420110_rule'
  tag stig_id: 'SRG-APP-000295-AU-000190'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-23626r420109_fix'
  tag 'documentable'
  tag legacy: ['SV-109119', 'V-100015']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
