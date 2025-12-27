control 'SV-80215' do
  title 'BlackBerry OS 10.3 must implement the management setting: disable lock screen preview of work content.'
  desc 'Sensitive data could be viewed if the preview of data on the locked screen is not disabled and could be exposed to unauthorized viewers.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry implements the management setting: disable lock screen preview of work content. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of IT policy rules.
6. Verify "Allow lock screen preview of work content" is not selected.

On the BlackBerry device: 
1. While holding the Power button from either the Work Space or Personal Space, select "Lock" to lock the device.
2. Verify the Work Space content is not visible on the lock screen.

If the BES IT policy rule "Allow lock screen preview of work content" is selected or on the BlackBerry device the Work Space content is visible on the lock screen, this is a finding. 

Note: Procedures above are for BES 12 only.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow lock screen preview of work content".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66381r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65725'
  tag rid: 'SV-80215r1_rule'
  tag stig_id: 'BB10-3X-001050'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71769r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
