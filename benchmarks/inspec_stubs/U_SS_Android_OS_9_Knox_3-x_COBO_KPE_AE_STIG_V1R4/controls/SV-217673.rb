control 'SV-217673' do
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
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18892r362048_chk'
  tag severity: 'medium'
  tag gid: 'V-217673'
  tag rid: 'SV-217673r617455_rule'
  tag stig_id: 'KNOX-09-000470'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-18890r362049_fix'
  tag 'documentable'
  tag legacy: ['SV-102971', 'V-92883']
  tag cci: ['CCI-000370', 'CCI-000381', 'CCI-000366']
  tag nist: ['CM-6 (1)', 'CM-7 a', 'CM-6 b']
end
