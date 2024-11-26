control 'SV-95045' do
  title 'Samsung Android 8 with Knox must be configured to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor, including biometric fingerprint, iris, face, voice, and hybrid authentication factor: Disable Face Recognition.

Note: This requirement is Not Applicable (NA) if the non-Password Authentication Factor mechanism is included in the products Common Criteria evaluation (fingerprint and iris scan are allowed).'
  desc "The Face Recognition feature allows a user's face to be registered and used to unlock the device. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1"
  desc 'check', 'Review documentation on Samsung Android 8 with Knox and inspect the configuration on Samsung Android 8 with Knox to disable Face Recognition.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Minimum Password Complexity" setting in the "Android Restrictions" rule. 
2. Verify the settings are "Alphanumeric".
3. Ask the MDM Administrator to display the "Face recognition" check box in the "Password Policy" rule. 
4. Verify the check box is deselected.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Select "Screen lock type".
4. Enter PIN.
5. "Face recognition" will be grayed out.

If the MDM console the "Face recognition" check box is not deselected or on the Samsung Android 8 device "Face recognition" is not grayed out, this is a finding.'
  desc 'fix', 'Configure the mobile operating system to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor (e.g., using a fingerprint, iris, face, voice, or hybrid authentication factor) unless the mechanism is DoD approved.

On the MDM console, deselect the "Face" check box in the "Android Password Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80013r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80341'
  tag rid: 'SV-95045r1_rule'
  tag stig_id: 'KNOX-08-011000'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-87147r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
