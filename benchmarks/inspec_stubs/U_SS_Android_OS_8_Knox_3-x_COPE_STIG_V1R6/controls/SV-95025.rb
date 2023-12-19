control 'SV-95025' do
  title 'Samsung Android 8 with Knox must be configured to not allow CONTAINER passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is prohibiting CONTAINER passwords with more than two repeating or sequential characters. If feasible, use a spare device to try to create a password with more than two repeating or sequential characters (e.g., bbb, 888, hij, 654). 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Maximum Sequential Characters" setting in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule. 
2. Verify the value of the setting is set to two or fewer sequential characters.
3. Ask the MDM Administrator to display the "Maximum Sequential Numbers" setting in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule. 
4. Verify the value of the setting is set to two or fewer sequential characters.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Select "Knox Settings".
3. Select "Lock type.
4. Enter current password.
5. Select "Password".
6. Attempt to enter a password that contains more than two sequential characters or sequential numbers.
7. Verify the password is not accepted.

If the MDM console "Maximum Sequential Character" and "Maximum Sequential Number" are set to more than two repeating or sequential characters for the Knox CONTAINER or on the Samsung Android 8 with Knox device, a password with more than two repeating or sequential characters is accepted for the Knox CONTAINER, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to prevent CONTAINER passwords from containing more than two repeating or sequential characters.

On the MDM console, do the following:
1. Set the "Maximum Sequential Characters" value to "2" in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule.
2. Set the "Maximum Sequential Numbers" value to "2" in the "Android Knox CONTAINER >> CONTAINER Password Restrictions" rule.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79993r1_chk'
  tag severity: 'low'
  tag gid: 'V-80321'
  tag rid: 'SV-95025r1_rule'
  tag stig_id: 'KNOX-08-008700'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-87127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
