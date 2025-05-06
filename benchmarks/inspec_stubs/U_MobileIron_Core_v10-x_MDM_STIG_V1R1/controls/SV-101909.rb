control 'SV-101909' do
  title 'The MobileIron Core v10 server must be able to limit user enrollment of devices that do not have required OS type and version.'
  desc 'Access control of mobile devices to DoD sensitive information or access to DoD networks must be controlled so that DoD data will not be compromised. The primary method of access control of mobile devices is via enrollment of authorized mobile devices on the MobileIron Core v10 server. Therefore, the MobileIron Core v10 server must have the capability to enforce a policy for this control.

SFR ID: FIA_ENR_EXT.1.2'
  desc 'check', 'Perform the following actions to verify users cannot enroll devices that do not have required OS type and version.

Task 1: Verify that the appropriate OSs are allowed to register. 
1. In the Admin Portal, go to Settings >> Users & Devices >> Registration.
2. Scroll to the "Platforms for Registration" section.
3. In the "Enabled Platforms" list, verify all inappropriate OSs are excluded.

If inappropriate OSs are able to register, this is a finding.

Task 2: Verify the OS version alert is setup.
1. Log on to the MobileIron Core Admin Portal.
2. In the Admin Portal, go to Logs >> Event Settings.
3. Select the appropriate Alert.
4. Select "Edit".
5. Verify “Disallowed {appropriate OS} version found” is selected for every managed OS and all other checkboxes are not selected.

If there is no OS version alert setup or the alert is not set up correctly, this is a finding.

Task 3: Verify a custom compliance action is setup.
1. Go to Policies & Configs >> Compliance Actions.
2. Select the desired compliance action.
3. Select "Actions".
4. Select "Edit".
5. Verify the following checkboxes are selected:
- Enforce Compliance Actions Locally on Devices
- Send a compliance notification or alert to the user
- Block email access and AppConnect apps
- Quarantine the device
- Remove All Configurations

If there is no custom compliance action setup or the custom compliance action is not set up correctly, this is a finding.

Task 4: Verify each appropriate security policy is setup to trigger a compliance action when OS violations occur.
1. In Admin Portal, go to Policies & Configs >> Policies.
2. Select the security policy you want to work with.
3. Click "Edit".
4. Scroll down to the "Access Control" section of the Modifying Security Policy dialog.
5. Under appropriate OS type, verify the checkbox for when "OS version is less than" has been selected.
6. On the same line, verify in the dropdown list, the appropriate custom compliance action is selected.
7. On the same line, in the dropdown list for appropriate OS versions, verify the appropriate OS version is selected.

If there is no compliance action setup for OS version in the security policy or the compliance action is not set up correctly, this is a finding.

Task 5: Verify the security policy is assigned to all applicable labels.
1. Go to Policies and Configs >> Policies.
2. For the security policy being verified, put cursor over the "Labels" column.
3. Verify the "Applied Label(s)" includes all desired labels.

If all desired labels are not selected in each appropriate policy, this is a finding.'
  desc 'fix', 'Complete the following actions to limit user enrollment of devices that do not have required OS type and version:

Task 1: Configure Operating Systems allowed to register.
1. In the Admin Portal, go to Settings >> Users & Devices >> Registration.
2. Scroll to the "Platforms for Registration" section.
3. In the "Enabled Platforms" list, select the platforms you want to exclude, selecting from: Android, iOS, OS X, Windows.
Note: Shift-click platforms to select more than one.
4. Click the left arrow button to move the selected platforms to the "Disabled Platforms list".
5. Click "Save".

Task 2: Configure OS version alert.
1. Log on to the "MobileIron Core Admin" Portal.
2. In the Admin Portal, go to Logs >> Event Settings.
3. Select Add New >> Policy Violations Event.
4. Enter a name for the event.
5. In the "Security Policy Triggers" section, look for the appropriate OS heading.
6. Confirm that the app control alert “Disallowed {appropriate OS} version found” is selected. Repeat for every managed OS.
7. Deselect all the other checkboxes. 
8. Repeat steps 5-7 for every managed OS.
9. In the "Apply to Labels" section, select the appropriate labels in the "Available" column.
10. Click the right arrow to move them to the "Selected" column.
11. Click "Save".

Task 3: Define a custom compliance action. 
1. Go to Policies & Configs >> Compliance Actions.
2. Click "Add+" to open the "Add Compliance Action" dialog.
3. Enter a name for the compliance action.
4. Select "Enforce Compliance Actions Locally on Devices".
5. In the "Alert" section, select "Send a compliance notification or alert to the user".
6. In the "Block Access" section, select "Block email access and AppConnect apps".
7. In the "Quarantine" section, select "Quarantine the device".
8. Select "Remove All Configurations".
9. Click "Save".

Task 4: Set up the security policy to trigger the compliance action when the violations occur.
1. In Admin Portal, go to Policies & Configs >> Policies.
2. Select the security policy you want to work with.
3. Click "Edit".
4. Scroll down to the "Access Control" section of the "Modifying Security Policy" dialog.
5. Under appropriate OS type, select the checkbox for "When OS version is less than".
6. On the same line, in the dropdown list, select the custom compliance action that you just created.
7. On the same line, in the dropdown list for appropriate OS versions, select the appropriate OS version.
8. Click "Save".

Task 5: Apply the security policy to a label that is also applied to the target devices.
1. Verify checkbox for the policy you are working with is selected.
2. Click Actions >> Apply to Label.
3. Select the appropriate label(s).
4. Click "Apply".'
  impact 0.5
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90965r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91807'
  tag rid: 'SV-101909r1_rule'
  tag stig_id: 'MICR-10-000020'
  tag gtitle: 'PP-MDM-312001'
  tag fix_id: 'F-98009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
