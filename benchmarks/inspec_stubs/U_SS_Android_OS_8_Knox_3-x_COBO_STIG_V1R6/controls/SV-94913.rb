control 'SV-94913' do
  title 'Samsung Android 8 with Knox must be configured to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor, including biometric fingerprint, iris, face, voice, and hybrid authentication factor: Disable Intelligent Scanning.

Note: This requirement is Not Applicable (NA) if the non-Password Authentication Factor mechanism is included in the products Common Criteria evaluation (fingerprint and iris scan are allowed).'
  desc "The Intelligent Scanning feature allows a user's face and iris to be registered and used such that either authentication method returning a match will unlock the device.

Intelligent Scanning combines the known weaknesses of iris and face scanning that could allow adversaries to unlock and gain access to the device.

Disabling this feature will mitigate this risk.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1"
  desc 'check', 'Review documentation on Samsung Android 8 with Knox and inspect the configuration on Samsung Android 8 with Knox to disable Face Recognition.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Minimum Password Complexity" setting in the "Android Restrictions" rule. 
2. Verify the settings are "Alphanumeric".
3. Ask the MDM Administrator to display the "Face recognition" and "Iris Scanner" check box in the "Password Policy" rule. 
4. Verify at least one of the check boxes is deselected.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Select "Screen lock type".
4. Enter PIN.
5. "Intelligent Scanning" will be grayed out.

If on the MDM console the "Face recognition" check box or the "Iris Scanner" check box is not deselected or on the Samsung 8 mobile device in the "Password Policy" rule "Intelligent Scanning" is not grayed out, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor (e.g., using a fingerprint, iris, face, voice, or hybrid authentication factor), unless the mechanism is DoD approved.

On the MDM console, deselect the "Face" or "Iris" check box in the "Android Password Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80209'
  tag rid: 'SV-94913r1_rule'
  tag stig_id: 'KNOX-08-010800'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-87015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
