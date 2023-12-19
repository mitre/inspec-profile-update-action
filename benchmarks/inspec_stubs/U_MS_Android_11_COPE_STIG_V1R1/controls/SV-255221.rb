control 'SV-255221' do
  title 'Microsoft Android 11 must allow the Administrator (EMM) to perform the following management function: Wipe Enterprise data.'
  desc "When a user's device is lost or stolen, it is useful to remotely wipe it as soon as possible to avoid loss of DOD sensitive information. The Administrator must have the capability to force a wipe on a lost or stolen device to reduce the risk of compromise of sensitive DOD data. This capability mitigates that risk.

SFR ID: FMT_SMF_EXT.1.1 #28"
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device function to wipe Enterprise data works.

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Managed work profile specific policies".
2. Select "Remove work profile".

On the Android 11 device, do the following:
Verify the work profile has been removed from the Android 11 device.

If the EMM cannot wipe enterprise data (work profile), this is a finding.'
  desc 'fix', 'To perform the wipe Enterprise of data function on a Microsoft Android 11 device (when required).

On the EMM console:
1. Open "Managed work profile specific policies".
2. Select "Remove work profile".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58834r870761_chk'
  tag severity: 'medium'
  tag gid: 'V-255221'
  tag rid: 'SV-255221r870833_rule'
  tag stig_id: 'MSFT-11-005400'
  tag gtitle: 'PP-MDF-302360'
  tag fix_id: 'F-58778r870762_fix'
  tag 'documentable'
  tag cci: ['CCI-000370', 'CCI-002242']
  tag nist: ['CM-6 (1)', 'AC-7 (2)']
end
