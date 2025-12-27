control 'SV-80255' do
  title 'BlackBerry OS 10.3 must prevent the use of BlackBerry Protect.'
  desc 'BlackBerry Protect gives users the ability to remotely lock, wipe, send audible alerts, and locate their BlackBerry device, but can become a maintainability issue for enterprise deployments. If a user forgets their BlackBerry ID password, the device must be sent back to BlackBerry to have the BlackBerry Protect feature disabled. In addition, BlackBerry Protect must be disabled by the user before it can be wiped and transferred to a new user.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry prevents the use of BlackBerry Protect.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Apps” group of IT policy rules.
6. Verify "Allow BlackBerry Protect" is not selected.

On the BlackBerry device: 
1. From either the Work Space or Personal Space, navigate to "Settings" >> "BlackBerry Protect".
2. Verify "BlackBerry Protect" is toggled to the left (off) and not accessible.

If the BES IT Policy rule "Prevent the use of BlackBerry Protect." is selected, or on the BlackBerry device if "BlackBerry Protect" is toggled to the right (on) and accessible, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Apps” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow BlackBerry Protect".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66447r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65765'
  tag rid: 'SV-80255r1_rule'
  tag stig_id: 'BB10-3X-020340'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71835r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
