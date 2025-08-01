control 'SV-80201' do
  title 'BlackBerry OS 10.3 must implement the management setting: must bind removable storage media cards to the mobile device via centrally managed policy. This requirement is applicable to Work space only activation Type.'
  desc 'The removable media card is an extension of the embedded device media. In order to protect sensitive data stored on the media card, the data must be encrypted and bound to the device such that it cannot be read by other mobile devices and computers.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry implements the management setting: must bind removable storage media cards to the mobile device via centrally managed policy. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of IT policy rules.
6. Verify "Force media card encryption" is selected.

On the BlackBerry device: 
1. Navigate to Settings >> Security and Privacy >> Encryption.
2. Verify "Media Card Encryption" is not a listed option.

If the BES IT policy rule "Force media card encryption" is not selected or on the BlackBerry device the "Media Card Encryption" is listed as an option, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Device Functionality” group of IT policy rules.
7. Select the check box next to the IT Policy "Force card encryption".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66365r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65711'
  tag rid: 'SV-80201r1_rule'
  tag stig_id: 'BB10-3X-000950'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71753r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
