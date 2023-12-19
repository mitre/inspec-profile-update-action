control 'SV-234036' do
  title 'Access to Tanium logs on each endpoint must be restricted by permissions.'
  desc 'For the Tanium Client software to run without impact from external negligent or malicious changes, the permissions on the Tanium log files and their directory must be restricted.

Tanium is deployed with a Client Hardening Solution. This solution, when applied, will ensure directory permissions are in place.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Actions".

Click on "Scheduled Actions".

Look for a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory".

If a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" does not exist, or there is a Scheduled Action contradicting the "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" scheduled action, this is a finding.

If the scheduled action exists, select it and if it is not approved (the "Approve" button at the top of the section will be displayed if not approved), this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

On the Dashboard, select "Client Service Hardening".

Select the "Set Client Directory Permissions".

Tanium will parse the script and return a row for "Restricted" and a row for "Not Restricted", with their respective client counts.

Click on the "Not Restricted" row.

Select "Deploy Action".

In the "Deploy Action" dialog box, the package "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" will be selected.

The clients, which have their Tanium Client directory "Not Restricted" will be displayed in the bottom window.

Choose a schedule to deploy the hardening.

Under "Targeting Criteria", in the Action Group, select "All Computers" from the drop-down.

Click on "Deploy Action".

Verify settings.

Click on "Show Client Status Details".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37221r610608_chk'
  tag severity: 'medium'
  tag gid: 'V-234036'
  tag rid: 'SV-234036r612749_rule'
  tag stig_id: 'TANS-CL-000002'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-37186r610609_fix'
  tag 'documentable'
  tag legacy: ['SV-102145', 'V-92043']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
