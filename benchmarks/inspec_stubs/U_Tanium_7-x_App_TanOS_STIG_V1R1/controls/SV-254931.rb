control 'SV-254931' do
  title 'The ability to uninstall the Tanium Client service must be disabled on all managed clients.'
  desc "By default, end users have the ability to uninstall software on their clients. In the event the Tanium Client software is uninstalled, the Tanium Server is unable to manage the client and must redeploy to the client. Preventing the software from being displayed in the client's Add/Remove Programs will lessen the risk of the software being uninstalled by non-Tanium System Administrators."
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under Actions, select "Scheduled Actions".

4. Look for a scheduled action titled "Client Service Hardening - Hide Client from Add-Remove Programs".

5. If a scheduled action titled "Client Service Hardening - Hide Client from Add-Remove Programs" does not exist, this is a finding.

If the scheduled action exists, select it and if it is not approved (the "Approve" button at the top of the section will be displayed if not approved), this is a finding.

If the scheduled action exists and has been approved but does not disable the visibility of the client in Add-Remove Programs, this is a finding.

If the action is not configured to repeat at least every hour, this is a finding.

If the scheduled action is not targeted at an "All Computers" Action Group, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Interact". 

4. In the "Categories" section, select "Client Service Hardening".

5. In "Dashboard" section, select "Hide From Add-Remove Program".

6. The results will show a "Count" of clients matching the "Tanium Client Visible in Add-Remove Programs" query.

7. Select the result line.

8. Choose "Deploy Action".

9. The "Deploy Action" dialog box will display "Client Service Hardening - Hide Client from Add-Remove Programs" as the package. The computer names comprising the "count" of noncompliant systems will be displayed in the bottom.

10. Deployment Package drop-down select "Client Service Hardening - Hide Client from Add-Remove Programs".

11. Configure the schedule to repeat at least every hour for the requested action.

12. Under "Targeting Criteria", in the "Action Group," select "All Computers" from the drop-down.

13. Click "Show preview to continue". Noncompliant systems will be displayed in the bottom.

14. Click "Deploy Action".

15. Verify settings.

16. Click "Show Client Status Details".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58544r867691_chk'
  tag severity: 'medium'
  tag gid: 'V-254931'
  tag rid: 'SV-254931r867693_rule'
  tag stig_id: 'TANS-AP-000805'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-58488r867692_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
