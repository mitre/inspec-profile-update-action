control 'SV-84709' do
  title 'Windows 10 Mobile must not allow passwords that include more than two repeating or sequential characters.'
  desc 'Password strength is a measure of the effectiveness of a password in resisting guessing and brute force attacks. Passwords that contain repeating or sequential characters are significantly easier to guess than those that do not contain repeating or sequential characters. Therefore, disallowing repeating or sequential characters increases password strength and decreases risk.

SFR ID: FMT_SMF_EXT.1.1 #01b'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device is prohibiting passwords with more than two repeating or sequential characters. If feasible, use a spare device to try to create a password with more than two repeating or sequential characters (e.g., bbb, 888, hij, 654).

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "Require simple password, no repeating or pattern based passwords".
3. Verify that setting restriction is turned off/disallowed.

On the Windows 10 Mobile device:

1. Wait for the MDM policy to be applied.
2. When prompted that the password policy has changed, attempt to set a password that is either 111111 or 123456.
3. Verify that those password types are not allowed. 

If the MDM system does not enforce a password policy that disables "Require simple password, no repeating or pattern based passwords" or on the phone creating simple password is allowed, this is a finding.'
  desc 'fix', 'Configure the MDM system to enforce a password policy that disables "Require simple password, no repeating or pattern based passwords".

Deploy the policy on managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70563r1_chk'
  tag severity: 'low'
  tag gid: 'V-70087'
  tag rid: 'SV-84709r1_rule'
  tag stig_id: 'MSWM-10-201003'
  tag gtitle: 'PP-MDF-201004'
  tag fix_id: 'F-76323r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
