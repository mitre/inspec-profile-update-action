control 'SV-91335' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Configure to enforce a minimum Container password length of 4 characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute-force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to enforce a minimum Container password length of "4" characters.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Minimum Length" setting in the "Android Knox Container >> Container Password Restrictions" rule. 
2. Verify the value of the setting is the same or greater than "4" characters.

On the Samsung Android 7 with Knox device, do the following:
1. Open the Knox Container.
2. Select "Knox Settings".
3. Select "Lock type".
4. Enter current password.
5. Attempt to enter a password with fewer than "4" characters.
6. Verify the password is not accepted.

If the MDM console "Minimum Length" is not set to the same or greater than "4" characters or on the Samsung Android 7 with Knox device, accepts a container password with fewer than the "4" characters, this is a finding.

Note: This configuration setting will allow users to implement fingerprint unlock for the container, which is approved for use. The use of a password to move between container and personal areas is only required if the password is needed to provide data separation between the two processing environments. For the Samsung devices, the password is required to enable the container and implement data separation.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce a minimum Container password length of four characters.

On the MDM console, set the "Minimum Length" value to "4" or greater in the "Android Knox Container >> Container Password Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76309r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76639'
  tag rid: 'SV-91335r1_rule'
  tag stig_id: 'KNOX-07-913200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83333r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
