control 'SV-80205' do
  title 'BlackBerry OS 10.3 must implement the management setting: disable the transfer of any file-based data via Bluetooth.'
  desc 'Bluetooth data transfers, except when using an approved smart card reader, do not use FIPS validated encryption. Therefore data transfer via Bluetooth must be disabled to mitigate the possible loss of sensitive DoD information.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry implements the management setting: disable the transfer of any file-based data via Bluetooth. This procedure is performed on only on the BES console.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users, in turn.
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
  tag check_id: 'C-66371r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65715'
  tag rid: 'SV-80205r1_rule'
  tag stig_id: 'BB10-3X-000980'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71759r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
