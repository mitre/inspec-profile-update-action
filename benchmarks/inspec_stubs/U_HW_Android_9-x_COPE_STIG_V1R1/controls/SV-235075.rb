control 'SV-235075' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39a'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the mobile device has a USB mass storage mode and whether it has been disabled. 

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open Device Restrictions.
2. Open Restrictions settings.
3. Ensure "Disallow usb file transfer" is selected.

On the Honeywell Android Pie device:
1. Plug USB cable into Android Pie device and connect to a non-DoD network-managed PC. 
2. Go to Settings >> Connected devices >> USB.
3. Ensure No data transfer is selected.

If the MDM console device policy is not set to disable USB mass storage mode or on the Honeywell Android Pie device, the device policy is not set to disable USB mass storage mode, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to disable USB mass storage mode.

On the MDM console:
1. Open Device Restrictions.
2. Open Restrictions settings.
3. Select "Disallow usb file transfer".'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38294r623240_chk'
  tag severity: 'medium'
  tag gid: 'V-235075'
  tag rid: 'SV-235075r626527_rule'
  tag stig_id: 'HONW-09-003500'
  tag gtitle: 'PP-MDF-301210'
  tag fix_id: 'F-38257r623241_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
