control 'SV-80209' do
  title 'BlackBerry OS 10.3 must implement the management setting: enforce the minimum password length for the Personal Space password to 4 digits. This requirement does not apply to the Work space only activation type.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute-force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise. A password is required for the Personal Space to stop access to the BlackBerry desktop by an unauthorized person. This is a mobile security best practice control.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry implements the management setting: enforce the minimum password length for the Personal Space password to 4 digits. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

This requirement can be enforced by two methods:
Method 1: Have the user set a personal space password of at least 4 characters.
Method 2: Force the Personal Space password to be the same as the Work Space password.

For Method 1:
On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Password” group of IT policy rules.
6. Verify "Require full device password" is selected.
7. Verify "Define work space and device password behavior" is set to "Different" or "User Choice".
On the BlackBerry Device:
8. Have user unlock the BlackBerry device.
9. Verify the user enters a password of at least 4 characters.

For Method 2:
On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Password” group of IT policy rules.
6. Verify "Require full device password" is selected.
7. Verify "Define work space and device password behavior" is set to "Same".

If the user is using a Personal Space password of less than 4 characters (for method 1) or the BES IT Policy rule "Require full device password" is not selected (for method 2), this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
For Method 1:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Password” group of IT policy rules.
7. Select the check box next to the IT Policy "Require full device password".
8. Set "Define work space and device password behavior" to "Different" or "User Choice" using the drop-down menu.
9. Have user unlock the BlackBerry device.
10. Verify the user enters a password of at least 4 characters.
11. Click "Save".

For Method 2:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Password” group of IT policy rules.
7. Select the check box next to the IT Policy "Require full device password".
8. Set "Define work space and device password behavior" to "Same" using the drop-down menu.
9. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66375r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65719'
  tag rid: 'SV-80209r1_rule'
  tag stig_id: 'BB10-3X-001000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71763r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
