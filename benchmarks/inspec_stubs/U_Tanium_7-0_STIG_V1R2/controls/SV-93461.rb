control 'SV-93461' do
  title 'Tanium must set an absolute timeout for sessions.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific application system functionality where the system owner, data owner, or organization requires additional assurance. Based upon requirements and events specified by the data or application owner, the application developer must incorporate logic into the application that will provide a control mechanism that disconnects users upon the defined event trigger. The methods for incorporating this requirement will be determined and specified on a case by case basis during the application design and development stages.

Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to re-authenticate, guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active."
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

In the "Show Settings Containing:" search box, type "session_expiration_seconds". Enter.

If no results are returned, this is a finding.

If results are returned for "session_expiration_seconds", but the value is not "900" or less, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console and then click on "Administration".

Select the "Global Settings" tab.

Click on "New Setting".

In the "New System Setting" dialog box, enter "session_expiration_seconds" for "Setting Name:".

Enter "900" or less for "Setting Value:".

Select "Server" from the "Affects" drop-down list.

Select "Numeric" from the "Value Type" drop-down list.

Click "Save".

If "session_expiration_seconds" exists but is not "900" or less, select the box beside the value and click on "Edit".

Enter "900" or less for "Setting Value:".

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78331r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78755'
  tag rid: 'SV-93461r1_rule'
  tag stig_id: 'TANS-SV-000066'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-85497r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
