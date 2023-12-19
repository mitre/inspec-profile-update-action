control 'SV-80189' do
  title 'BlackBerry OS 10.3 must not allow the USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry does not allow a USB mass storage mode. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Device functionality” group of IT policy rules.
6. Verify "Allow USB OTG mass storage" is not selected.

On the BlackBerry device: 
1. On the BlackBerry device attach a Micro USB OTG to USB 2.0 adapter cable to the BlackBerry Micro USB port.
2. Connect USB drive to the adapter cable.
3. Open file manager icon on the BlackBerry.
4. Tap the three horizontal lines on the bottom left of the screen.
5. Verify the USB drive is not listed.

If the BES IT policy rule "USB OTG Mass Storage" is selected or the BlackBerry device file manager application displays a USB drive, this is a finding. 

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Device functionality” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow USB OTG mass storage". 
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66353r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65699'
  tag rid: 'SV-80189r1_rule'
  tag stig_id: 'BB10-3X-000250'
  tag gtitle: 'PP-MDF-201016'
  tag fix_id: 'F-71741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
