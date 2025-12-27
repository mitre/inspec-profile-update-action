control 'SV-93295' do
  title 'The permissions on the Tanium Client directory must be restricted to only the SYSTEM account on all managed clients.'
  desc "By restricting access to the Tanium Client directory on managed clients, the Tanium client's ability to operate and function as designed will be protected from malicious attack and unintentional modifications by end users."
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Scheduled Actions" tab.

Look for a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on the Tanium Client directory".

If a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on the Tanium Client directory" does not exist, this is a finding.

If the scheduled action exists, select it and if it is not approved (the "Approve" button at the top of the section will be displayed if not approved), this is a finding.

If the scheduled action exists and has been approved but does not disable the visibility of the client in Add-Remove Programs, this is a finding.

If the action is not configured to repeat at least every hour, this is a finding.'
  desc 'fix', %q(Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

From the Dashboard, under "Client Service Hardening", click on "Set Client Directory Permissions".

The results will show a "Count" of clients' compliant and non-compliant hardening for the "Tanium Client Directory Permissions".

Non-compliant clients will have a count other than "0" for "Not Restricted" or "Error: No Permissions".

Select each of the "Not Restricted" or "Error: No Permissions" statuses.

Select "Deploy Action".

In the "Deploy Action" dialog box change the package to "Client Service Hardening - Set SYSTEM only permissions on the Tanium Client directory" as the package.

Configure the schedule to repeat at least every hour for the requested action.

Under "Targeting Criteria", in the Action Group select "All Computers" from the drop-down.

Click on "Show preview to continue". Non-compliant systems will be displayed in the bottom.

Click on "Deploy Action".

Verify settings.

Click on "Show Client Status Details".)
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78589'
  tag rid: 'SV-93295r1_rule'
  tag stig_id: 'TANS-CL-000007'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-85325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
