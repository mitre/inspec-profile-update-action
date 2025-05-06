control 'SV-86115' do
  title 'The BlackBerry OS 10.3 The BlackBerry OS 10.3 smartphone must close the Hotspot Browser connection if the user does not log into the Hotspot Browser after 15 minutes (or less).'
  desc 'This configuration setting sets the amount of time the hotspot browser remains open without login.  The hotspot browser could be at risk of attack by an adversary if it remains open when not being used by the handset user.  It is a best practice to close the browser when not in use.'
  desc 'check', 'Review the BlackBerry OS 10.3 smartphone configuration settings to determine if the BlackBerry Hotspot Browser connection closes if the user does not log into the Hotspot Browser after "15" minutes (or less).  This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the side of the screen.
2. Expand the "IT policies" tab on the left pane.
3. Select and open each IT policy assigned to users, in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Device Functionality” group of "IT policy" rules
6. Verify "Hotspot Browser timeout " is set to "15" minutes.

On the BlackBerry device: 
1. From either the Work Space or Personal Space, navigate to "Settings" >> "Networks and Connections" >> "Wi-Fi", and connect to an available mobile hotspot connection.
2. Verify that all browsers are closed on the device.
3. Verify that the mobile hotspot connection disconnects after "15" minutes or less of inactivity.

If the BES IT policy rule "Hotspot Browser timeout " is not set to "15" minutes or less, or if the mobile hotspot connection does not disconnect after "15" minutes or less of inactivity, this is a finding.

Note:  Procedures above are for BES 12 only.  BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the side of the screen.
2. Expand the "IT policies" tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click "pencil icon" (upper right corner) to edit the IT Policy.
6. Scroll down to the “Device Functionality” group of IT policy rules
7. Set  "Hotspot Browser timeout" to "15" minutes or less.
8. Click "Save".

Note:  Procedures above are for BES 12 only.  BES 10 procedures may be slightly different.'
  impact 0.3
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-71881r2_chk'
  tag severity: 'low'
  tag gid: 'V-71491'
  tag rid: 'SV-86115r1_rule'
  tag stig_id: 'BB10-3X-001060'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-77811r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
