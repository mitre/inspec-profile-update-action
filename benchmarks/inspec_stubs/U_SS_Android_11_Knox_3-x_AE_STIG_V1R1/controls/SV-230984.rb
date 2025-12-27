control 'SV-230984' do
  title 'Samsung Android must be configured to disable Face Recognition.

NOTE: This requirement is not applicable (NA) for specific biometric authentication factors included in the product Common Criteria evaluation.'
  desc 'The fingerprint reader can be used to authenticate the user in order to unlock the mobile device. At this time, no mobile device biometric reader has been evaluated as meeting the security requirements of the MDFPP or been approved for DoD use on mobile devices. This technology could allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review Samsung Android configuration settings to determine if Face Recognition is disabled.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "Face" is set to "Disable".

On the Samsung Android device: 
1. Open Settings >> Lock screen >> Screen lock type.
2. Enter current password.
3. Verify that "Face" is disabled and cannot be enabled.

If on the management tool "Face" is not set to "Disable", or on the Samsung Android device "Face" can be enabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android to disable Face Recognition.

On the management tool, in the device restrictions section, set "Face" to "Disable".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33914r592444_chk'
  tag severity: 'medium'
  tag gid: 'V-230984'
  tag rid: 'SV-230984r607691_rule'
  tag stig_id: 'KNOX-11-004100'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-33887r592445_fix'
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-000366', 'CCI-000370']
  tag nist: ['CM-7 a', 'CM-6 b', 'CM-6 (1)']
end
