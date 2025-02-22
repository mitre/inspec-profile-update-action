control 'SV-91303' do
  title 'The Samsung Android 7 with Knox must be configured to disable Phone Visibility.'
  desc 'Phone Visibility feature allows other devices to find your phone (Galaxy S8) and transfer files. Your phone will appear in the list of available devices when files are transferred via Transfer files to devices.

This feature can potentially result in unauthorized access to and compromise of sensitive DoD files. Disabling this feature will mitigate this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'If the feature is not present as described on a specific device model, this requirement is Not Applicable (NA).

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to disable Phone Visibility.

This validation procedure is performed on the Samsung Android 7 with Knox device only.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "Connections".
3. Select "Phone visibility".
4. Verify this is disabled.

If the Samsung Android 7 with Knox device, "Phone Visibility" is not set to disabled, this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User Based Enforcement (UBE) requirement.'
  desc 'fix', 'If the feature is not present as described on a specific device model, this requirement is Not Applicable (NA).

Configure the Samsung Android 7 with Knox to disable Phone Visibility.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "More" under Wireless and networks.
3. Disable "Phone visibility".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76277r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76607'
  tag rid: 'SV-91303r1_rule'
  tag stig_id: 'KNOX-07-017200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83301r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
