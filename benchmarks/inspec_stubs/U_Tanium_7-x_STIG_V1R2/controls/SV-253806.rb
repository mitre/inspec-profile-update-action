control 'SV-253806' do
  title 'Access to Tanium logs on each endpoint must be restricted by permissions.'
  desc 'For the Tanium Client software to run without impact from external negligent or malicious changes, the permissions on the Tanium log files and their directory must be restricted.

Tanium is deployed with a Client Hardening Solution. This solution, when applied, will ensure directory permissions are in place.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Actions", select "Scheduled Actions".

4. Look for a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory".

If a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" does not exist, or there is a Scheduled Action contradicting the "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" scheduled action, this is a finding.

If the scheduled action exists, select it. If it is not approved (the "Approve" button at the top of the section will be displayed if not approved), this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Modules" on the top navigation banner. 

3. Click "Interact".

4. Within "Interact", under "Explore Data", ask the question "Get Tanium Client Directory Permissions from all machines".

Tanium will parse the script and return a row for "Restricted" and a row for "Not Restricted", with their respective client counts.

5. Click the "Not Restricted" row.

6. Select "Deploy Action".

- In the "Deploy Action" dialog box, the package "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" will be selected.
- The clients, which have their Tanium Client directory "Not Restricted", will be displayed in the bottom window.

7. Choose a schedule to deploy the hardening.

8. Under "Targeting Criteria", in the "Action Group", select "All Computers" from the drop-down menu.

9. Click "Deploy Action".

10. Verify settings.

11. Click "Show Client Status Details".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57258r842444_chk'
  tag severity: 'medium'
  tag gid: 'V-253806'
  tag rid: 'SV-253806r842446_rule'
  tag stig_id: 'TANS-CL-000002'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-57209r842445_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
