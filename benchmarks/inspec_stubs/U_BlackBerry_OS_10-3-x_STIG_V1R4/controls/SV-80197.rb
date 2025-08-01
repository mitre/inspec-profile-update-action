control 'SV-80197' do
  title 'BlackBerry OS 10.3 must be configured to prevent non-approved updates of system software.'
  desc 'FOTA allows the user to download and install firmware updates over-the-air. These updates can include OS upgrades, security patches, bug fixes, new features and applications. Since the updates are controlled by the carriers, DoD will not have an opportunity to review and update policies prior to update availability to end users. Disabling FOTA will mitigate the risk of allowing users access to applications that could compromise DoD sensitive data. After reviewing the update and adjusting any necessary policies (i.e., disabling applications determined to pose risk), the administrator can re-enable FOTA.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry is configured to prevent non-approved updates of system software. This procedure is performed only on the BES console.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Device functionality” group of IT policy rules.
6. Verify "Allow wireless software updates" is set to "allow".
7. Verify a Device SR requirement profile is assigned to every user:
-Click on "Users and Devices" tab at the top of the screen.
-Select at least 5 random users in-turn
-Select the user
-Verify a Device SR requirement profile is listed under IT policy and profile
Note: Step 7 above will, by default, verify "Maximum software release version" has a value.

If the BES IT policy rule "Allow wireless software updates" is not selected and a Device SR requirement profile has not been assigned to all users, this is a finding. 

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Device functionality” group of IT policy rules.
7. Select the check box next to the IT Policy "Allow wireless software updates".
8. Assign SR requirement profile to every user.
9. Click "Save".

Note: If an SR requirements profile does not exist, you must create one before it can be assigned.

To create a device SR requirements profile:
1. Select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Select the "+" beside Device SR requirements in the menu.
3. Type a name and description for the profile.
4. Type a name and description for the profile.
5. Select the "Make update required" check box.
6. In the "Minimum software release version" drop-down list, select the minimum software version that a BlackBerry 10 device must be running.
7. In the "Maximum software release version" drop-down list, select the maximum software version that a BlackBerry 10 device must be running.
8. Click "Save".
9. Click "Add".

To Assign the SR requirements policy to a user:
1. On the menu bar, click "USER AND DEVICES".
2. For all applicable users, select the user from the list.
3. Click "+" beside "IT policy and profiles".
4. Select "Device SR requirements" from menu.
5. Select the appropriate Device SR requirements profile from the drop down menu".
6. Click "Assign".

To Assign the SR requirements policy to a group:
1. On the menu bar, click "GROUPS".
2. For all applicable groups, select the group from the list.
3. Click "Settings" tab.
4. Click "+" beside "IT policy and profiles".
5. Select "Device SR requirements" from menu.
6. Select the appropriate Device SR requirements profile from the drop down menu".
7. Click "Assign".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66361r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65707'
  tag rid: 'SV-80197r1_rule'
  tag stig_id: 'BB10-3X-000380'
  tag gtitle: 'PP-MDF-201031'
  tag fix_id: 'F-71749r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
