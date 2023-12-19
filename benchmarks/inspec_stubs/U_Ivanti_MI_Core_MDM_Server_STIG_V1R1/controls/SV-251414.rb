control 'SV-251414' do
  title 'The Ivanti MobileIron Core server must automatically terminate a user session after an organization-defined period of user inactivity.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific application system functionality where the system owner, data owner, or organization requires additional assurance. Based upon requirements and events specified by the data or application owner, the application developer must incorporate logic into the application that will provide a control mechanism that disconnects users upon the defined event trigger. The methods for incorporating this requirement will be determined and specified on a case-by-case basis during the application design and development stages.

"
  desc 'check', 'Review the MDM server or platform configuration and verify the server is configured to lock after 15 minutes of inactivity.

If, in the Admin Portal, Settings >> General >> Timeout is not set to 15 minutes or less, this is a finding.

The current value for the session timeout will be displayed in minutes.'
  desc 'fix', 'Configure the MDM server or platform to lock the server after 15 minutes of inactivity.

In the Admin Portal, go to Settings >> General >> Timeout.

From the dropdown menu, choose a timeout value of 5, 10, or 15 minutes.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54849r806372_chk'
  tag severity: 'medium'
  tag gid: 'V-251414'
  tag rid: 'SV-251414r806374_rule'
  tag stig_id: 'IMIC-11-007900'
  tag gtitle: 'SRG-APP-000295-UEM-000169'
  tag fix_id: 'F-54802r806373_fix'
  tag satisfies: ['FMT_SMF.1.1(2) b \nReference: PP-MDM-431014']
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
