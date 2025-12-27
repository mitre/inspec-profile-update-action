control 'SV-80179' do
  title 'BlackBerry OS 10.3 must not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #02'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry allows more than 10 consecutive failed authentication attempts. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Password” group of IT policy rules.
6. Verify "Maximum password attempts" is set to "10" or less.

On the BlackBerry device:
1a. For "Work-Only" activation type: navigate to Settings >> Security and Privacy >> Device Password and select "Change Device Password". Enter incorrect device password one time. Verify the error message shows "Incorrect password (n/x)" where x is 10 or less.
1b. For "Work and personal - Corporate" and "Work and personal - Regulated" activation types: navigate to Settings >> Security and Privacy >> Device Password and select "BlackBerry Balance" and verify "Password Attempt Limit" drop down box is “10” or less.

If the BES IT policy rule "Maximum Password Attempts" is not set to "10" or less or on the BlackBerry device the "Password Attempt Limit" drop down box is more than “10” (for "Work and personal - Corporate" and "Work and personal - Regulated" activation types) or has an error message of "Incorrect password (n/x)" where x is more than “10” (for "Work-Only" activation type), this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Password” group of IT policy rules.
7. Set "Maximum password attempts" to "10" or less.
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.3
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66337r3_chk'
  tag severity: 'low'
  tag gid: 'V-65689'
  tag rid: 'SV-80179r1_rule'
  tag stig_id: 'BB10-3X-000140'
  tag gtitle: 'PP-MDF-201005'
  tag fix_id: 'F-71727r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
