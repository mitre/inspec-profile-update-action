control 'SV-103891' do
  title 'Samsung Android must be configured to not allow backup of [all applications, configuration data] to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review device configuration settings to confirm that backup to locally connected systems has been disabled. 

Disabling backup to locally connected systems is validated by the validation procedure in "Disable USB mass storage", which is included in KNOX-09-000680.

Review device configuration settings to confirm that USB file transfer has been disallowed. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Android user restrictions" group, verify that "disallow usb file transfer" is selected. 

Connect the Samsung Android device to a non-DoD network-managed PC with a USB cable. 

On the PC, browse the mounted Samsung Android device and verify that it does not display any folders or files. 

If on the MDM console "disallow USB file transfer" is not selected, or the PC can mount and browse folders and files on the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable backup to locally connected systems. 

Disabling backup to locally connected systems is implemented by the configuration policy rule "Disable USB mass storage", which is included in KNOX-09-000680.

On the MDM console, for the device, in the "Android user restrictions" group, select "disallow USB file transfer".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(AE)'
  tag check_id: 'C-93123r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93805'
  tag rid: 'SV-103891r1_rule'
  tag stig_id: 'KNOX-09-000840'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-100051r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
