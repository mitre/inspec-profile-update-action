control 'SV-258633' do
  title 'Samsung Android must be configured to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor: Face recognition.'
  desc 'The biometric factor can be used to authenticate the user to unlock the mobile device. Unapproved/evaluated biometric mechanisms could allow unauthorized users to have access to DOD sensitive data if compromised. By not permitting the use of unapproved/evaluated biometric authentication mechanisms, this risk is mitigated.

SFR ID: FMT_SMF_EXT.1.1 #22, FIA_UAU.5.1'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling face recognition.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool in the device restrictions, verify "Face recognition" is set to "Disable".

On the Samsung Android device: 
1. Open Settings >> Lock screen >> Screen lock type.
2. Enter current password.
3. Verify "Face" is disabled and cannot be enabled.

If on the management tool "Face recognition" is not set to "Disable", or on the Samsung Android device "Face" can be enabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable face recognition.

On the management tool, in the device restrictions, set "Face recognition" to "Disable".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62373r931097_chk'
  tag severity: 'medium'
  tag gid: 'V-258633'
  tag rid: 'SV-258633r931099_rule'
  tag stig_id: 'KNOX-14-110080'
  tag gtitle: 'PP-MDF-333110'
  tag fix_id: 'F-62282r931098_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
