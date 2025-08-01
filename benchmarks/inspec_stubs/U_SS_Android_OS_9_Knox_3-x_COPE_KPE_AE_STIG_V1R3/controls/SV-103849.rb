control 'SV-103849' do
  title 'Samsung Android must be configured to disable exceptions to the access control policy that prevents [application processes, groups of application processes] from accessing [all, private] data stored by other [application processes, groups of application processes].'
  desc 'App data sharing gives apps the ability to access the data of other apps for enhanced user functionality. However, sharing also poses a significant risk that unauthorized users or apps will obtain access to DoD sensitive information. To mitigate this risk, there are data sharing restrictions. If a user is allowed to make exceptions to the data sharing restriction policy, the user could enable unauthorized sharing of data, leaving it vulnerable to breach. Limiting the granting of exceptions to either the administrator or common application developer mitigates this risk. 

Copying/pasting data between applications in different application processes or groups of application processes is considered an exception to the access control policy and therefore, the administrator must be able to enable/disable the feature. Other exceptions include allowing any data or application sharing between process groups.

SFR ID: FMT_SMF_EXT.1.1 #42, FDP_ACF_EXT.1.2'
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that the access control policy that prevents groups of application processes from accessing all data stored by other groups of application processes has been enabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the Workspace, in the "Knox RCP" group, do the following: 
1. Verify that "allow move applications to workspace" is not selected. 
2. Verify that "allow move files to personal" is not selected. 
3. Verify that "allow sharing clipboard to personal" is not selected. 
4. Verify that "sync calendar to personal" is not selected. 
5. Verify that "sync contact to personal" is not selected. 

On the Samsung Android device, do the following: 
1. Swipe up to access the App screen. 
2. Tap the "Workspace" tab. 
3. Open the "My Files" app. 
4. Find a file and select it with a long tap. 
5. From the Overflow menu (three vertical dots), tap "Move to Personal". 
6. Verify that the message "Security policy restricts this action" is displayed. 
7. Navigate back to the "Workspace" App screen and, using any Workspace app, copy text to the clipboard. 
8. Navigate to the "Personal" App screen and, using a Personal app, verify that the clipboard text cannot be pasted. 
9. Open Settings. 
10. Tap "Workspace". 
11. Verify that "Install apps" is disabled and cannot be tapped. 
12. Tap "Notifications and data". 
13. Verify that "Export calendar to Personal" is disabled and cannot be enabled. 

This is a finding if, on the MDM console: 
- "allow move applications to workspace" is selected; 
- "allow move files to personal" is selected; 
- "allow sharing clipboard to personal" is selected; 
- "sync calendar to personal" is enabled is selected; or 
- "sync contact to personal" is selected. 

This is a finding if, on the Samsung Android device: 
- "Move to Personal" file is not blocked; 
- Clipboard text can be pasted to Personal app; 
- "Install apps" is enabled or can be tapped; or 
- "Export calendar to Personal" is enabled or can be enabled.'
  desc 'fix', 'Configure the Samsung Android Workspace to enable the access control policy that prevents groups of application processes from accessing all data stored by other groups of application processes. 

On the MDM console, for the Workspace, in the "Knox RCP" group, do the following: 
1. Unselect "allow move applications to workspace". 
2. Unselect "allow move files to personal". 
3. Unselect "allow sharing clipboard to personal". 
4. Unselect "sync calendar to personal". 
5. Unselect "sync contact to personal". 

Note: The "allow move files to workspace" option may be selected if there is a DoD mission need for this feature.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(AE)'
  tag check_id: 'C-93081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93763'
  tag rid: 'SV-103849r1_rule'
  tag stig_id: 'KNOX-09-000240'
  tag gtitle: 'PP-MDF-301260'
  tag fix_id: 'F-100009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002191']
  tag nist: ['CM-6 b', 'AC-4 (2)']
end
