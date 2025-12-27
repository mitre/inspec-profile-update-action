control 'SV-254930' do
  title 'Control of the Tanium Client service must be restricted to SYSTEM access only for all managed clients.'
  desc "The reliability of the Tanium client's ability to operate depends upon controlling access to the Tanium client service. By restricting access to SYSTEM access only, the non-Tanium system administrator will not have the ability to impact operability of the service."
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under Actions, select "Scheduled Actions".

4. Look for a scheduled action titled "Client Service Hardening - Allow Only Local SYSTEM to Control Service".

If a scheduled action titled "Client Service Hardening - Allow Only Local SYSTEM to Control Service" does not exist, this is a finding.

5. If the scheduled action exists, select it and if it is not approved (the "Approve" button at the top of the section will be displayed if not approved), this is a finding.

If the scheduled action exists and has been approved but does not restrict control of the Tanium Client service to "Allow Only Local SYSTEM to Control Service," this is a finding.

If the action is not configured to repeat at least every hour, this is a finding.

If the scheduled action is not targeted at an "All Computers" Action Group, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Interact". 

4. In "Categories" section, select "Client Service Hardening".

5. In "Dashboards" section, select "Control Service State Permissions".

6. The results will show a "Count" of clients matching the "Service Control is set to default permissions" query.

7. Select the result line for "Service Control is set to default permissions".

8. Choose "Deploy Action".

9. Deployment Package drop-down select "Client Service Hardening - Allow Only Local SYSTEM to Control Service".

10. Configure the schedule to repeat at least every hour for the requested action.

11. Under "Targeting Criteria" in the Action Group, select "All Computers" from the drop-down.

12. Click "Show preview to continue".

13. Noncompliant systems will be displayed at the bottom.

14. Click "Deploy Action".

15. Verify settings.

16. Click "Show Client Status Details".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58543r867688_chk'
  tag severity: 'medium'
  tag gid: 'V-254930'
  tag rid: 'SV-254930r867690_rule'
  tag stig_id: 'TANS-AP-000800'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-58487r867689_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
