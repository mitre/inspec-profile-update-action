control 'SV-252863' do
  title 'Zebra Android 11 must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39a'
  desc 'check', 'Review Zebra Android device configuration settings to determine if the mobile device has a USB mass storage mode and whether it has been disabled. 

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM console, do the following:
1. Open "User restrictions on parent".
2. Verify that "Disallow USB file transfer" is toggled to "On".

On the Android 11 device, do the following:
1. Plug a USB cable into Android 11 device and connect to a non-DoD network-managed PC. 
2. Go to Settings >> Connected devices >> USB.
3. Ensure "No data transfer" is selected.

If the EMM console device policy is not set to disable USB mass storage mode or on the Android 11 device, the device policy is not set to disable USB mass storage mode, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 11 device to disable USB mass storage mode.

On the EMM console:
1. Open "User restrictions on parent".
2. Toggle "Disallow USB file transfer".'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56319r820514_chk'
  tag severity: 'medium'
  tag gid: 'V-252863'
  tag rid: 'SV-252863r820516_rule'
  tag stig_id: 'ZEBR-11-003500'
  tag gtitle: 'PP-MDF-301210'
  tag fix_id: 'F-56269r820515_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
