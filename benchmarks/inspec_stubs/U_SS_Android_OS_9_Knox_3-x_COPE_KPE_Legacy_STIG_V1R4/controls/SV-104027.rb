control 'SV-104027' do
  title 'Samsung Android Workspace must be configured to enforce a minimum password length of four characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute-force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that passwords with less than four characters are prevented. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the Workspace, in the "Knox password constraints" group, verify that "minimum password length" is "4" or greater. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Workspace". 
3. Tap "Lock type". 
4. Enter current password. 
5. Tap "Password". 
6. Verify that passwords with less than four characters are not accepted. 

If on the MDM console "minimum password length" is greater than "4", or if on the Samsung Android device a password with fewer than four characters is accepted, this is a finding. 

Note: This configuration setting will allow users to implement fingerprint unlock for the CONTAINER, which is approved for use. The use of a password to move between CONTAINER and personal areas is only required if the password is needed to provide data separation between the two processing environments. For the Samsung devices, the password is required to enable the CONTAINER and implement data separation.'
  desc 'fix', 'Configure Samsung Android Workspace to enforce a minimum password length of four characters. 

On the MDM console, for the Workspace, in the "Knox password constraints" group, set "minimum password length" to "4" or greater.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(Legacy)'
  tag check_id: 'C-93259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93941'
  tag rid: 'SV-104027r1_rule'
  tag stig_id: 'KNOX-09-001455'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-100189r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
