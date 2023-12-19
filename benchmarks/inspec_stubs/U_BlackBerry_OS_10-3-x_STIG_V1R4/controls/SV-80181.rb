control 'SV-80181' do
  title 'BlackBerry OS 10.3 must not allow protocols supporting wireless remote access connections.'
  desc "Having wireless remote access connections enabled could allow establishment of unauthorized remote access connections, which may give an adversary unintended capabilities. These remote access connections would expose the mobile device to additional risk, thereby increasing the likelihood of compromise of the confidentiality and integrity of its resident data. In this context, tethering refers to wired connections to an external device and not use of the device as a hotspot. A mobile device providing personal hotspot functionality is not considered wireless remote access if the functionality only provides access to a distribution network (such as a mobile carrier's cellular data network) and does not provide access to local applications or data.

SFR ID: FMT_SMF_EXT.1.1 #23"
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry does not allow protocols supporting wireless remote access connections. This procedure is performed only on the BES console.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Device Functionality” group of IT policy rules.
6. Verify "Allow transfer of work files using Bluetooth OPP or a Wi-Fi Direct connection" is not selected.

If the BES IT policy rule "Allow transfer of work files using Bluetooth OPP or a Wi-Fi Direct connection" is selected, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Device Functionality” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow transfer of work files using Bluetooth OPP or a Wi-Fi Direct connection".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66345r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65691'
  tag rid: 'SV-80181r1_rule'
  tag stig_id: 'BB10-3X-000180'
  tag gtitle: 'PP-MDF-201009'
  tag fix_id: 'F-71733r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000063', 'CCI-000366']
  tag nist: ['AC-17 a', 'CM-6 b']
end
