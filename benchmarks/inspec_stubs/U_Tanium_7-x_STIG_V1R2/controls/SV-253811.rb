control 'SV-253811' do
  title 'The permissions on the Tanium Client directory must be restricted to only the SYSTEM account on all managed clients.'
  desc "By restricting access to the Tanium Client directory on managed clients, the Tanium client's ability to operate and function as designed will be protected from malicious attack and unintentional modifications by end users."
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Actions", select "Scheduled Actions".

4. Look for a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on the Tanium Client directory".

If a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on the Tanium Client directory" does not exist, this is a finding.

If the scheduled action exists, select it. If it is not approved (the "Approve" button at the top of the section will be displayed if not approved), this is a finding.

If the scheduled action exists and has been approved but does not disable the visibility of the client in Add-Remove Programs, this is a finding.

If the action is not configured to repeat at least every 12 hours, this is a finding.

If the scheduled action is not targeted at an "All Computers" Action Group, this is a finding.'
  desc 'fix', %q(1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Interact". 

4. In "Categories" section, select box for "Client Service Hardening".

5. In "Dashboard" section, select "Set Client Directory Permissions".

- The results will show a "Count" of clients' compliant and noncompliant hardening for the "Tanium Client Directory Permissions".
- Noncompliant clients will have a count other than "0" for "Not Restricted" or "Error: No Permissions".

6. Select each of the "Not Restricted" or "Error: No Permissions" statuses.

7. Select "Deploy Action".

8. In the "Deploy Action" dialog box, change the package to "Client Service Hardening - Set SYSTEM only permissions on the Tanium Client directory" as the package.

9. Configure the schedule to repeat at least every 12 hours for the requested action.

10. Under "Targeting Criteria", in the Action Group, select "All Computers" from the drop-down menu.

11. Click "Show preview to continue". Noncompliant systems will be displayed in the bottom.

12. Click "Deploy Action".

13. Verify settings.

14. Click "Show Client Status Details".)
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57263r842459_chk'
  tag severity: 'medium'
  tag gid: 'V-253811'
  tag rid: 'SV-253811r850167_rule'
  tag stig_id: 'TANS-CL-000007'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-57214r842460_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
