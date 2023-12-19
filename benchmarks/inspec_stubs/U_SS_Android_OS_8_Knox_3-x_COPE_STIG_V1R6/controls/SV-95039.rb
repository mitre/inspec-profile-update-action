control 'SV-95039' do
  title 'Samsung Android 8 with Knox must be configured to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor, including biometric fingerprint, iris, face, voice, hybrid authentication factor: Disable Trust Agents.

Note: This requirement is Not Applicable (NA) if the non-Password Authentication Factor mechanism is included in the products Common Criteria evaluation (fingerprint and iris scan are allowed).'
  desc 'Trust Agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review documentation on Samsung Android 8 with Knox and inspect the configuration on Samsung Android 8 with Knox to disable Trust Agents.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Minimum Password Complexity" setting in the "Android Password Restrictions" rule. 
2. Verify the settings are "Alphanumeric".
3. Ask the MDM Administrator to display the "Disable Keyguard Trust Agents" check box in the "Android Password Restrictions" rule. 
4. Verify the check box is selected.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Select "Other security settings".
4. Select "Trust agents".
5. Verify all Trust Agents are disabled (grayed out) and cannot be enabled.

If the MDM console "Disable Keyguard Trust Agents" check box is not selected, or if "Minimum Password Complexity" is not configured to "Alphanumeric", or on the Samsung Android 8 with Knox device, the user can enable the settings, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor (e.g., using a fingerprint, iris, face, voice, or hybrid authentication factor) unless the mechanism is DoD approved.

Configure Samsung Android 8 with Knox to disable Trust Agents.

On the MDM console, select the "Disable Keyguard Trust Agents" setting in the "Android Password Restrictions" rule.

Note: Disabling Trust Agents will disable Smart Lock.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80007r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80335'
  tag rid: 'SV-95039r1_rule'
  tag stig_id: 'KNOX-08-010300'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-87141r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
