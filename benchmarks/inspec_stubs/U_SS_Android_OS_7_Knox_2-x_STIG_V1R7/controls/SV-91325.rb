control 'SV-91325' do
  title 'The Samsung Android 7 with Knox platform must implement the management setting Disable Nearby devices.'
  desc 'The Nearby devices feature allows the user to share files with other devices that are connected on the same WiFi access point using the DLNA technology. Even though the user must allow requests from other devices, this feature can potentially result in unauthorized access to and compromise of sensitive DoD files. Disabling this feature will mitigate this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This validation procedure is performed on the Samsung Android 7 with Knox device.

On the Samsung Android 7 with Knox device:
1. Open the device settings.
2. Select "More connection settings".
3. Select "Nearby devices".
4. Verify this is disabled.

If setting is enabled and cannot be disabled, this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User Based Enforcement (UBE) requirement.'
  desc 'fix', 'Configure the mobile operating system to disable Nearby devices.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76299r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76629'
  tag rid: 'SV-91325r1_rule'
  tag stig_id: 'KNOX-07-019100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83323r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
