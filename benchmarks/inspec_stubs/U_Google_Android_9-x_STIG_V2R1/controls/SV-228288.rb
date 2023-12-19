control 'SV-228288' do
  title 'Google Android Pie must be configured to disable trust agents. Note: This requirement is not applicable (NA) for specific biometric authentication factors included in the products Common Criteria evaluation.'
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review device configuration settings to confirm that trust agents are disabled. 

This procedure is performed on both the MDM Administration console and the Google Android Pie device. 

On the MDM console:
1. Open restrictions section.
2. Set "Disable trust agents" to on.

On the Google Android Pie device: 
1. Open Settings. 
2. Tap "Security & location". 
3. Tap "Advanced". 
4. Tap "Trust agents". 
5. Verify that all listed trust agents are disabled and cannot be enabled. 

If on the MDM console "disable trust agents" is not selected, or on the Android Pie device a trust agent can be enabled, this is a finding.'
  desc 'fix', 'Configure Google Android Pie to disable trust agents. 

On the MDM console:
1. Open Lock screen restrictions section.
2. Set "Disable trust agents" to on.'
  impact 0.5
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30521r494931_chk'
  tag severity: 'medium'
  tag gid: 'V-228288'
  tag rid: 'SV-228288r617455_rule'
  tag stig_id: 'GOOG-09-002300'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-30506r494932_fix'
  tag 'documentable'
  tag legacy: ['SV-106429', 'V-97325']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
