control 'SV-237180' do
  title 'ColdFusion must execute as a non-privileged user.'
  desc 'Privileged user accounts are accounts that have access to all the system resources.  These accounts are reserved for administrative users and applications that have a need for such unfettered access.  

Because ColdFusion does not need to run with access to all the system resources, the ColdFusion services must be setup to execute as unprivileged users.  This protects server resources, OS hosted applications, and organization resources should the ColdFusion application server become compromised.'
  desc 'check', 'For ColdFusion running on Windows: 
1. Run the snap-in services.msc.
2. Locate the ColdFusion section of services.
3. Right click on each ColdFusion service and select "Properties".
4. Select the "Log On" tab.

If any service has "Local System account" selected, this is a finding.

5. View the groups for each user account that was used to run a ColdFusion service by running the snap-in compmgmt.msc.
6. Expand the "Local Users and Groups" in the left pane under "System Tools" to view the "Users" and "Groups" folders.
7. Select the "Users" folder and the users will be listed in the right pane.
8. Right click a user that runs a ColdFusion service.
9. Select "Properties" on the menu.
10. Select the "Member Of" tab.

If any groups are listed, this is a finding.

11.  Click on the "Remote Desktop Services Profile" tab.

If the "Deny this user permissions to log on to Remote Desktop Session Host server" is not checked, this is a finding.

12 Repeat steps 8 through 11 for each user that runs a ColdFusion service.

ColdFusion running on Linux:
1. Locate the file coldfusion_11 by running the command: find / -name coldfusion_11
2. Change to the directory where the file is located.
3. Execute the command: grep -i -m 1 runtime_user coldfusion_11
4. The user being used to execute ColdFusion will be listed.  
5. View the user within the /etc/passwd file.
6. Make note of the user id and group id.  For example, if the line in the passwd file is cfuser:x:500:501:ColdFusion:/home/cfuser:/sbin/nologin, the user id is 500 and the group id is 501.

If the user id or the group id is set to 0 (zero), this is a finding.'
  desc 'fix', 'For ColdFusion running on Windows: 
1. Create a user for the ColdFusion services by running the snap-in compmgmt.msc.
2. Expand the "Local Users and Groups" in the left pane under "System Tools" to view the "Users" and "Groups" folders.
3. Select the "Users" folder.
4. Right click in the right pane and select "New User".
5. Enter a username and password for the user.  Follow any organization specific policies in place and Windows STIGs for password complexity, usernames, etc.
6. Select the "Create" button to create the user.
7. Right click on the new user and select the "Properties" menu item.  
8. Select the "Member Of" tab.
9. Remove all groups.
10. Select the "Remote Desktop Services Profile" tab.
11. Check the "Deny this user permissions to log on to Remote Desktop Session Host server" checkbox.
12. Select the "Apply" button.
13. Run the snap-in services.msc.
14. Locate the ColdFusion services.
15. Right click on a ColdFusion service and select "Properties".
16. Select the "Log On" tab.
17. Click on the "This account:" radio button.
18. Enter the username and password for the user account that was just created.
19. Select "Ok" to save the changes.
20. Repeat steps 15 through 19 for each ColdFusion service.

ColdFusion running on Linux:
1. Create a group for the user account that will run the ColdFusion service by executing the command groupadd.  For example, if the group being created is webusers, the command would be: groupadd webusers
2. Create the user account for the service by executing the command adduser.  For example, if the user being created is cfuser with the group webusers, the command would be: adduser -g webusers -s /sbin/nologin -M -c ColdFusion cfuser
3. Assign a password to the account that follows any organization password policies in place and the OS STIG for password complexity.  The password is assigned by executing the command: passwd cfuser
4. Locate the file coldfusion_11 by running the command: find / -name coldfusion_11
5. Change to the directory where the file is located.
6. Edit the coldfusion_11 file.
7. Locate the text RUNTIME_USER= within coldfusion_11
8. Update the user account being used to run the ColdFusion service.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40399r641633_chk'
  tag severity: 'medium'
  tag gid: 'V-237180'
  tag rid: 'SV-237180r641635_rule'
  tag stig_id: 'CF11-03-000111'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-40362r641634_fix'
  tag 'documentable'
  tag legacy: ['SV-76923', 'V-62433']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
