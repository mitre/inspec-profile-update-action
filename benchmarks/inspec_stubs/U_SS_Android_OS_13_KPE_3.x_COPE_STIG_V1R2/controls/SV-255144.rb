control 'SV-255144' do
  title 'Samsung Android must be configured to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor, including face recognition.'
  desc 'The biometric factor can be used to authenticate the user to unlock the mobile device. Unapproved/evaluated biometric mechanisms could allow unauthorized users to have access to DOD sensitive data if compromised. By not permitting the use of unapproved/evaluated biometric authentication mechanisms, this risk is mitigated.

SFR ID: FMT_SMF_EXT.1.1 #22, FIA_UAU.5.1'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling Face Recognition.

This validation procedure is performed on both the management tool and the Samsung Android device.

If a KPE premium license is activated, Facial Recognition will be automatically disabled.

Otherwise, on the management tool in the device restrictions, verify "Face recognition" is set to "Disable".

On the Samsung Android device: 
1. Open Settings >> Lock screen >> Screen lock type.
2. Enter current password.
3. Verify "Face" is disabled and cannot be enabled.

If on the management tool a KPE premium license is not activated and "Face Recognition" is not set to "Disable", or on the Samsung Android device "Face" can be enabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable Face Recognition.

This policy is included to allow a Samsung Android device to be deployed without an activated KPE premium license. If a license is activated, Facial Recognition will be automatically disabled. In this case, this policy does not need to be configured for STIG compliance, as Face as a biometric will be disabled.

On the management tool, in the device restrictions, set "Face Recognition" to "Disable".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58757r867367_chk'
  tag severity: 'medium'
  tag gid: 'V-255144'
  tag rid: 'SV-255144r867369_rule'
  tag stig_id: 'KNOX-13-210080'
  tag gtitle: 'PP-MDF-323110'
  tag fix_id: 'F-58701r867368_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
