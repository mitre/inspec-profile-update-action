control 'SV-84715' do
  title 'Windows 10 Mobile must enforce a minimum password length of 6 characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. The ability to crack a password is a function of how many attempts an adversary is permitted, how quickly an adversary can do each attempt, and the size of the password space. The longer the minimum length of the password is, the larger the password space. Having a too-short minimum password length significantly reduces password strength, increasing the chance of password compromise and resulting device and data compromise.

SFR ID: FMT_SMF_EXT.1.1 #01a'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device is enforcing a minimum password length of 6 characters. If feasible, use a spare device to try to create a password with less than 6 characters using a standard user account.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to display the device password settings.
2. Verify that a password required setting is in effect.
3. Verify the minimum length for the password is set to 6 or greater.

On the Windows 10 Mobile device:

1. Go to Settings/Accounts/Sign-in options and tap on Change under the PIN section. 
2. Attempt to change the password to a five-digit password. 
3. Verify Windows 10 Mobile rejects the new password with a message of Your PIN must be at least 6 characters long. 

If the password policy on the MDM is not set to require a password with a minimum length of at least 6, or a device accepts a passcode of less than 6 characters, this is a finding.'
  desc 'fix', 'Configure the MDM system to enforce a password required as well as a minimum length password of 6 characters for device unlock. 

Deploy the policy on managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70569r1_chk'
  tag severity: 'low'
  tag gid: 'V-70093'
  tag rid: 'SV-84715r1_rule'
  tag stig_id: 'MSWM-10-201012'
  tag gtitle: 'PP-MDF-201002'
  tag fix_id: 'F-76329r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
