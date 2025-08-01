control 'SV-80195' do
  title 'BlackBerry OS 10.3 must be configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (HandsFree Profile), and SPP (Serial Port Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled.

SFR ID: FMT_SMF_EXT.1.1 #20'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry is configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (HandsFree Profile), and SPP (Serial Port Profile). This procedure is performed on only on the BES console.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Device functionality” group of IT policy rules.
6. Verify the following IT Policies are not selected:
- Allow Bluetooth file transfer using OBEX
- Allow Bluetooth MAP
- Allow transfer work messages using Bluetooth MAP without prompt
- Allow Bluetooth PAN profile
- Allow transfer of work messages using Bluetooth MAP
- Allow Bluetooth Contacts Transfer Using PBAP
- Allow Transfer of Work Contacts Using Bluetooth PBAP or HFP

If any of the following the BES IT policy rules is selected , this is a finding:
- Allow Bluetooth file transfer using OBEX
- Allow Bluetooth MAP
- Allow transfer work messages using Bluetooth MAP without prompt
- Allow Bluetooth PAN profile
- Allow transfer of work messages using Bluetooth MAP
- Allow Bluetooth Contacts Transfer Using PBAP
- Allow Transfer of Work Contacts Using Bluetooth PBAP or HFP

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Unselect the check box next to the following IT Policies:
- Allow Bluetooth file transfer using OBEX
- Allow transfer work messages using Bluetooth MAP without prompt
- Allow Bluetooth MAP
- Allow Bluetooth PAN profile
- Allow transfer of work messages using Bluetooth MAP
- Allow Bluetooth Contacts Transfer Using PBAP
- Allow Transfer of Work Contacts Using Bluetooth PBAP or HFP.
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66359r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65705'
  tag rid: 'SV-80195r1_rule'
  tag stig_id: 'BB10-3X-000340'
  tag gtitle: 'PP-MDF-201027'
  tag fix_id: 'F-71747r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
