control 'SV-80203' do
  title 'BlackBerry OS 10.3 must implement the management setting: disable Bluetooth Discoverable Mode via centrally managed policy. This requirement only applies to Work space only and Work and personal - Regulated activation types.'
  desc 'Bluetooth usage could provide an attack vector for a hacker to connect to a BlackBerry device without the knowledge of the user. Disabling Discoverable mode reduces the risk of a non-authorized Bluetooth device connecting the DoD BlackBerry.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry implements the management setting: disable Bluetooth Discoverable Mode via centrally managed policy. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Device Functionality” group of IT policy rules.
6. Verify "Allow Bluetooth discoverable mode" is not selected.

On the BlackBerry device:
1. From either the Work Space or Personal Space, navigate to "Settings" >> "Network and Connections" >> "Bluetooth”.
2. Turn on Bluetooth.
3. Verify "Discoverable Mode" is set to "off" and greyed out.

If the BES IT policy rule "Allow Bluetooth discoverable mode" is selected or on the BlackBerry device the "Discoverable Mode" is not set to "off" and greyed out, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Device Functionality” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow Bluetooth discoverable mode".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66367r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65713'
  tag rid: 'SV-80203r1_rule'
  tag stig_id: 'BB10-3X-000970'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71755r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
