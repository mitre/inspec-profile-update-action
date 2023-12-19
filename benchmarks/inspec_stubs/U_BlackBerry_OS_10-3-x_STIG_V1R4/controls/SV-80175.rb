control 'SV-80175' do
  title 'BlackBerry OS 10.3 must enforce a minimum password length of 6 characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #01a'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if a minimum password length of 6 characters is enforced. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Setting” and “BlackBerry” tabs.
5. Scroll down to the “Password” group of IT policy rules.
6. Verify "Minimum password length" is set to "6".

On the BlackBerry device: 
1a. For "Work-Only" activation type: navigate to Settings >> Security and Privacy >> Device Password and select "Change Password".
1b. For "Work and personal - Corporate" and "Work and personal - Regulated" activation types: navigate to Settings >> Security and Privacy >> Device Password and select "BlackBerry Balance" and select "Change Password".
2. Authenticate using the current password.
3. Attempt to change the password to a length of less than 6 characters.
4. Select "Password Rules" and verify the message "Your password must be at least 6 characters." is displayed.

If the BES IT policy rule "Minimum Password Length" is not set to "6", or the BlackBerry device allows a new password to be set with less than 6 characters, this is a finding. 

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Password” group of IT policy rules.
7. Set "Minimum password length" to "6".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.3
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66319r3_chk'
  tag severity: 'low'
  tag gid: 'V-65685'
  tag rid: 'SV-80175r1_rule'
  tag stig_id: 'BB10-3X-000110'
  tag gtitle: 'PP-MDF-201002'
  tag fix_id: 'F-71709r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
