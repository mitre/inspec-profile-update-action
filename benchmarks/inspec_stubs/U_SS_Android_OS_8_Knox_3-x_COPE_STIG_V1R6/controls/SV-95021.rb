control 'SV-95021' do
  title 'Samsung Android 8 with Knox must implement the management setting: Configure to enforce a minimum CONTAINER password length of four characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute-force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to enforce a minimum CONTAINER password length of four characters.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Minimum Length" setting in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule. 
2. Verify the value of the setting is the same or greater than the required length.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Select "Workspace settings".
3. Select "Lock type".
4. Enter current password.
5. Attempt to enter a password with fewer characters than the required length.
6. Verify the password is not accepted.

If the MDM console "Minimum Length" is not set to the same or greater than the required length or if the Samsung Android 8 with Knox device accepts a CONTAINER password with fewer characters than the required length, this is a finding. 

Note: This configuration setting will allow users to implement fingerprint unlock for the CONTAINER, which is approved for use. The use of a password to move between CONTAINER and personal areas is only required if the password is needed to provide data separation between the two processing environments. For the Samsung devices, the password is required to enable the CONTAINER and implement data separation.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce a minimum CONTAINER password length of four characters.

On the MDM console, set the "Minimum Length" value to "4" or greater in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79989r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80317'
  tag rid: 'SV-95021r1_rule'
  tag stig_id: 'KNOX-08-008400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87123r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
