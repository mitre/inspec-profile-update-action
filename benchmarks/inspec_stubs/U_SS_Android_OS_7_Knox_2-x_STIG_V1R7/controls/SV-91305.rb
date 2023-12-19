control 'SV-91305' do
  title 'The Samsung Android 7 with Knox must be configured to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor. Disable Face Recognition.'
  desc 'The Face Recognition feature allows users face to be registered and used to unlock the device. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review documentation on the Samsung Android 7 with Knox and inspect the configuration on the Samsung Android 7 with Knox to disable Face Recognition.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Application disable list" setting in the "Android Application" rule. 
2. Verify the list contains all Face Recognition related packages.

On the Samsung Android 7 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Verify "Face Recognition" status is "Register your face".
4. When an attempt is made to register your face, the function does not work.

If the Samsung Android 7 with Knox device, "Face Recognition" function works, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable Face Recognition.

On the MDM console, add all packages associated with the Face Recognition feature to the "Application disable list" setting in the "Android Applications" rule. 

Note: Refer to the Supplemental document for additional information.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76279r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76609'
  tag rid: 'SV-91305r1_rule'
  tag stig_id: 'KNOX-07-017400'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-83303r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
