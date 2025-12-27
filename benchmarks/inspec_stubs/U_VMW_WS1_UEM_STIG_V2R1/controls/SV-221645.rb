control 'SV-221645' do
  title 'Authentication of MDM platform accounts must be configured so they are implemented via an enterprise directory service.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire Workspace ONE UEM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the Workspace ONE UEM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FIA'
  desc 'check', %q(Review the MDM platform to verify user and administrator authentication is implemented via an enterprise directory service.

On the Workspace ONE UEM console complete the following procedure to ensure that the Workspace ONE UEM (MDM) Server is configured to leverage an enterprise authentication mechanism, and that Workspace ONE UEM users and administrators can only use directory accounts to enroll into the Workspace ONE UEM (MDM) Server:

1. For Workspace ONE UEM server Platform configuration, refer to "https://docs.vmware.com/en/VMware-Workspace-ONE-UEM/1907/Directory_Service_Integration/GUID-AWT-DIRECTORYSERVICESOVERVIEW.html".
2. Log in to the Workspace ONE UEM Administration console.
3. Choose "Groups and Settings".
4. Choose "All Settings".
5. Under "System" heading, choose "Enterprise Integration".
6. Choose "Directory Services".
7. Under "Server" tab, verify directory service connection information.
8. Under "User" tab, verify User Group connection information.
9. Under "Group" tab, verify Group connection information.
10. Choose "X" to close screen.
11. Choose "Groups and Settings".
12. Choose "All Settings".
13. Under "Devices and Users", choose "General".
14. Choose "Enrollment".
15. On "Authentication Modes" setting, verify only the box titled "Directory" is selected.

If on the Workspace ONE UEM server console "Directory" is not selected as the authentication mode, this is a finding.

If the MDM platform user authentication is not implemented via an enterprise directory service, this is a finding.

To verify administrators can only use directory services accounts:
16. Choose Accounts >> Administrators >> List View.
17. Review user types under the Admin Type heading. If any users have an Admin Type of "Basic", this is a finding.

Exception: One local "Emergency" account may remain that uses WS1 authentication services.

To verify users can only use directory services accounts:
18. Choose Accounts >> Users >> List View.

If only a small number of user accounts are listed, it is recommended to use the following steps:
a. Under the "General Info" tab, click on each username link to view the user's summary data.
b. Under "Type" in the "User Info" column, if "Basic" is listed, this is a finding.
c. Choose "List View" again to be presented with the list of user accounts and repeat steps a and b until the full set of user accounts has been examined.

If a large number of user accounts are listed, it is recommended to use the following steps instead:
a. Choose the "Export" drop-down and select the format to be used for the export list.
b. An "Export List" pop-up window will appear with instructions on where to locate and examine the exported list of user accounts.
c. Examine the exported list. If any user accounts are denoted as Basic in the Security Type column, this is a finding.)
  desc 'fix', %q(Configure the MDM platform so that user and administrator authentication is implemented via an enterprise directory service.

On the Workspace ONE UEM console complete the following procedure to ensure that the Workspace ONE UEM (MDM) Server is configured to leverage an enterprise authentication mechanism, and that Workspace ONE UEM users can only use directory accounts to enroll into the Workspace ONE UEM (MDM) Server:

Exception: One local "Emergency" account may remain that uses WS1 authentication services.

1. For Workspace ONE UEM server Platform configuration, refer to "https://docs.vmware.com/en/VMware-Workspace-ONE-UEM/1907/Directory_Service_Integration/GUID-AWT-DIRECTORYSERVICESOVERVIEW.html".
2. Log in to the Workspace ONE UEM Administration console.
3. Choose "Groups and Settings".
4. Choose "All Settings".
5. Under "System" heading, choose "Enterprise Integration".
6. Choose "Directory Services".
7. Under "Server" tab, verify directory service connection information. If not set according to organizational rules, modify the directory service connection to the correct setting.
8. Under "User" tab, verify User Group connection information. If not set according to organizational rules, modify the User Group connection to the correct setting.
9. Under "Group" tab, verify Group connection information. If not set according to organizational rules, modify the Group connection to the correct setting.
10. If any changes made to Server, User, or Group settings, click "Save".
11. Choose "X" to close screen.
12. Choose "Groups and Settings".
13. Choose "All Settings".
14. Under "Devices and Users", choose "General".
15. Choose "Enrollment".
16. On the "Authentication Modes" setting, verify only the box titled "Directory" is selected. If "Directory" is unchecked, select it. If any other boxes are checked, uncheck them.
17. If any changes were made to "Authentication Modes" settings, click "Save".
18. Choose "X" to close the window.

To verify and remove any administrator accounts that are not Directory Service accounts:
19. Choose Accounts >> Administrators >> List View.
20. Review user types under the "Admin Type" heading, and select all users, and only users, with an Admin Type of "Basic". Do NOT select users with an Admin Type of "Directory". Selecting one or more users with the Basic Admin Type will cause the "More Actions" drop-down to appear.
21. From the More Actions drop down, select "Delete". This will result in an "Are you sure you want to delete this record?" pop-up box asking to confirm deletion of the selected account(s).
22. Click "OK" to delete the selected accounts.

To verify and remove any user accounts that are not Directory Service accounts:
23. Choose Accounts >> Users >> List View.

If only a small number of user accounts are listed, it is recommended to use the following steps:
a. Under the "General Info" tab, click each username link to view the user's summary data.
b. Under "Type" in the "User Info" column, if "Basic" is listed, the user account must be removed. Choose the "More" drop-down and select "Delete". A pop-up window will appear stating whether the user was successfully deleted. Click "OK" to close the window.
c. Choose "List View" again to be presented with the list of user accounts and repeat steps a and b until the full set of user accounts has been examined.

If a large number of user accounts are listed, it is recommended to use the following steps instead:
a. Choose the "Export" drop-down and select the format to be used for the export list.
b. An "Export List" pop-up window will appear with instructions on where the exported list of user accounts is located.
c. Examine the exported list. If any user accounts are denoted as "Basic" in the "Security Type" column, the account must be deleted.
d. To delete a user account, click the username link of the user account under "List View". Choose the "More" drop-down and select "Delete". A pop-up window will appear stating whether the user was successfully deleted. Click "OK" to close the window.
e. Choose "List View" again to be presented with the list of remaining user accounts and repeat step d until all user accounts with a Security Type of "Basic" have been deleted.)
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23360r805066_chk'
  tag severity: 'medium'
  tag gid: 'V-221645'
  tag rid: 'SV-221645r807442_rule'
  tag stig_id: 'VMW1-00-000630'
  tag gtitle: 'PP-MDM-414003'
  tag fix_id: 'F-23349r807441_fix'
  tag 'documentable'
  tag legacy: ['SV-111289', 'V-102333']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
