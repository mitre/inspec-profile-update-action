control 'SV-80177' do
  title 'BlackBerry OS 10.3 must lock the Work Space after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #01b'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the Work Space locks after 15 minutes (or less) of inactivity. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Password” group of IT policy rules.
6. Verify "Security timeout" is set to "15 minutes" or less.

On the BlackBerry device: 
1. From either the Work Space or Personal Space, navigate to Settings >> Security and Privacy >> Device Password.
2. Verify "Lock Device After" is set to "15 Minutes" or less, with higher values hidden.

If the BES IT policy rule "Security Timeout" is not set to "15 minutes" or less or on the BlackBerry device "Lock Device After" is set to more than "15 Minutes", this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Password” group of IT policy rules.
7. Set "Security timeout" to "15 minutes" or less.
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66331r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65687'
  tag rid: 'SV-80177r1_rule'
  tag stig_id: 'BB10-3X-000120'
  tag gtitle: 'PP-MDF-201003'
  tag fix_id: 'F-71719r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
