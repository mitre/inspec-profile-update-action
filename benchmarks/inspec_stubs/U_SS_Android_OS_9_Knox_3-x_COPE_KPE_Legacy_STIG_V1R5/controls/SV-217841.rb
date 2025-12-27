control 'SV-217841' do
  title 'Samsung Android Workspace must be configured to not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #1b'
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that passwords with two repeating or sequential characters are prevented. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the Workspace, do the following: 
1. In the "Knox password constraint" group, verify that "maximum sequential characters" is "2" or less. 
2. In the "Knox password constraint" group, verify that "maximum sequential numbers" is "2" or less. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Workspace". 
3. Tap "Lock type". 
4. Enter current password. 
5. Tap "Password". 
6. Verify that passwords with two or more sequential characters or numbers are not accepted. 

If on the MDM console "maximum sequential characters" or "maximum sequential numbers" is more than "2", or on the Samsung Android device a password with two or more sequential characters or numbers is accepted, this is a finding.'
  desc 'fix', 'Configure Samsung Android Workspace to prevent passwords from containing more than two repeating or sequential characters. 

On the MDM console, for the Workspace, in the "Knox password constraints" group: 
1. Set "maximum sequential characters" to "2". 
2. Set "maximum sequential numbers" to "2".'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19057r362981_chk'
  tag severity: 'low'
  tag gid: 'V-217841'
  tag rid: 'SV-217841r388482_rule'
  tag stig_id: 'KNOX-09-001465'
  tag gtitle: 'PP-MDF-301020'
  tag fix_id: 'F-19055r362982_fix'
  tag 'documentable'
  tag legacy: ['SV-104029', 'V-93943']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
