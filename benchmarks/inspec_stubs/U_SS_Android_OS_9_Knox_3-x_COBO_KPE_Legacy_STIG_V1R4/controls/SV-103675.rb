control 'SV-103675' do
  title 'Samsung Android must be configured to disable trust agents. Note: This requirement is not applicable (NA) for specific biometric authentication factors included in the products Common Criteria evaluation.'
  desc 'Trust agents allow a user to unlock a mobile device without entering a passcode when the mobile device is, for example, connected to a user-selected Bluetooth device or in a user-selected location. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review device configuration settings to confirm that trust agents are disabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Android lock screen restrictions" group, verify that "disable trust agents" is selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Biometrics and security". 
3. Tap "Other security settings". 
4. Tap "Trust agents". 
5. Verify that all listed trust agents are disabled and cannot be enabled. 

If on the MDM console "disable trust agents" is not selected, or on the Samsung Android device a trust agent can be enabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable trust agents. 

On the MDM console, for the device, in the "Android lock screen restriction" group, select "disable trust agents".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(Legacy)'
  tag check_id: 'C-92905r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93589'
  tag rid: 'SV-103675r1_rule'
  tag stig_id: 'KNOX-09-000475'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-99833r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
