control 'SV-230090' do
  title 'The Motorola Android Pie must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39a'
  desc 'check', 'Review Motorola Android device configuration settings to determine if the mobile device has a USB mass storage mode and whether it has been disabled. 

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console: 
1. Open Device Restrictions.
2. Open Restrictions Settings.
3. Verify "Disallow usb file transfer" is selected.

On the Android Pie device: 
1. Plug USB cable into Android Pie device and connect to a non-DoD network-managed PC. 
2. Go to Settings >> Connected devices >> USB.
3. Verify "No data transfer" is selected.

If the MDM console device policy is not set to disable USB mass storage mode, or on the Android Pie device, the device policy is not set to disable USB mass storage mode, this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to disable USB mass storage mode.

On the MDM console: 
1. Open Device Restrictions.
2. Open Restrictions Settings.
3. Select "Disallow usb file transfer".'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32405r538266_chk'
  tag severity: 'medium'
  tag gid: 'V-230090'
  tag rid: 'SV-230090r569708_rule'
  tag stig_id: 'MOTO-09-003500'
  tag gtitle: 'GOOG-09-003500'
  tag fix_id: 'F-32383r538267_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
