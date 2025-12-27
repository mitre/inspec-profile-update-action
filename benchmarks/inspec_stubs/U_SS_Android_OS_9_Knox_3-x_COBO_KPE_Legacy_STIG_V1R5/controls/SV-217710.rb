control 'SV-217710' do
  title 'Samsung Android must be configured to enforce a minimum password length of six characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #1a'
  desc 'check', 'Review device configuration settings to confirm that the minimum password length is six or more characters. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Android password constraints" group, verify that the "minimum password length" is "6" or greater. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Lock screen". 
3. Tap "Screen lock type". 
4. Enter current password. 
5. Tap "Password". 
6. Verify that passwords entered with fewer than six characters are not accepted. 

If on the MDM console "minimum password length" is less than "6", or on the Samsung Android device a password of less than "6" characters is accepted, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enforce a minimum password length of six characters. 

On the MDM console, in the Android password constraints, set the "minimum password length" to "6" or greater.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18928r362278_chk'
  tag severity: 'low'
  tag gid: 'V-217710'
  tag rid: 'SV-217710r378766_rule'
  tag stig_id: 'KNOX-09-000375'
  tag gtitle: 'PP-MDF-301010'
  tag fix_id: 'F-18926r362279_fix'
  tag 'documentable'
  tag legacy: ['SV-103667', 'V-93581']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
