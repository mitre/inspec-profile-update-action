control 'SV-103873' do
  title 'Samsung Android must be configured to disable Face Recognition. Note: This requirement is not applicable (NA) for specific biometric authentication factors included in the products Common Criteria evaluation.'
  desc "The Face Recognition feature allows a user's face to be registered and used to unlock the device. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1"
  desc 'check', 'Review device configuration settings to confirm that Face Recognition is disabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Android lock restrictions" group, verify that "disable face" is selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Lock screen". 
3. Tap "Screen lock type". 
4. Enter current password. 
5. Verify that "Face" is disabled and cannot be enabled. 

If on the MDM console "disable face" is not selected, or on the Samsung Android device "Face" can be enabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable Face Recognition. 

On the MDM console, for the device, in the "Android lock screen restriction" group, select "disable face".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(AE)'
  tag check_id: 'C-93105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93787'
  tag rid: 'SV-103873r1_rule'
  tag stig_id: 'KNOX-09-000500'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-100033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
