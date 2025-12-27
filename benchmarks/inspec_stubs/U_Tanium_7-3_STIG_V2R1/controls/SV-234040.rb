control 'SV-234040' do
  title 'The ability to uninstall the Tanium Client service must be disabled on all managed clients.'
  desc "By default, end users have the ability to uninstall software on their clients. In the event the Tanium Client software is uninstalled, the Tanium Server is unable to manage the client and must redeploy to the client. Preventing the software from being displayed in the client's Add/Remove Programs will lessen the risk of the software being uninstalled by non-Tanium System Administrators."
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Scheduled Actions" tab.

Look for a scheduled action titled "Client Service Hardening - Hide Client from Add-Remove Programs".

If a scheduled action titled "Client Service Hardening - Hide Client from Add-Remove Programs" does not exist, this is a finding.

If the scheduled action exists, select it and if it is not approved (the "Approve" button at the top of the section will be displayed if not approved), this is a finding.

If the scheduled action exists and has been approved but does not disable the visibility of the client in Add-Remove Programs, this is a finding.

If the action is not configured to repeat at least every hour, this is a finding.

If the scheduled action is not targeted at an "All Computers" Action Group, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

From the Dashboard, under "Client Service Hardening", click on "Hide From Add-Remove Programs".

The results will show a "Count" of clients matching the "Tanium Client Visible in Add-Remove Programs" query.

Select the result line.

Choose "Deploy Action".

The "Deploy Action" dialog box will display "Client Service Hardening - Hide Client from Add-Remove Programs" as the package. The computer names comprising the "Count" of non-compliant systems will be displayed in the bottom.

Deployment Package drop-down select "Client Service Hardening - Hide Client from Add-Remove Programs".

Configure the schedule to repeat at least every hour for the requested action.

Under "Targeting Criteria", in the Action Group, select "All Computers" from the drop-down.

Click on "Show preview to continue". Non-compliant systems will be displayed in the bottom.

Click on "Deploy Action".

Verify settings.

Click on "Show Client Status Details".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37225r610620_chk'
  tag severity: 'medium'
  tag gid: 'V-234040'
  tag rid: 'SV-234040r612749_rule'
  tag stig_id: 'TANS-CL-000006'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-37190r610621_fix'
  tag 'documentable'
  tag legacy: ['SV-102153', 'V-92051']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
