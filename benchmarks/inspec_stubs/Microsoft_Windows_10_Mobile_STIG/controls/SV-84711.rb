control 'SV-84711' do
  title 'Windows 10 Mobile must not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #02'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts at 10 or less. If feasible, use a spare device to determine how many consecutive failed authentication attempts are permitted.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to display the device password settings. Check that these settings are configured:
2. Verify that the number of repeated sign-in failures before device is wiped is set to 10 or less.

On the Windows 10 Mobile device:

1. Ensure that the device has timed out or power cycled so that the lockscreen is shown.
2. Attempt to unlock the device using an incorrect PIN.
3. On the last attempt a warning will be presented and ask the user to enter A1B2C3. This is to ensure that random logon attempts were not being pocket dialed. Once A1B2C3 is entered a final attempt to unlock the phone can be made.
4. Verify that after the 10th attempt or less, the message Goodbye is displayed as the Windows 10 Mobile device reboots and wipes/hard resets. 

If the MDM is not configured to wipe the device in 10 password entry attempts or less or the device does not wipe after 10 password entry attempts to unlock it, this is a finding.'
  desc 'fix', 'Configure the MDM system to enforce a local device wipe after 10 or less repeated sign-in failures. 

Deploy the policy on managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70565r1_chk'
  tag severity: 'low'
  tag gid: 'V-70089'
  tag rid: 'SV-84711r1_rule'
  tag stig_id: 'MSWM-10-201008'
  tag gtitle: 'PP-MDF-201005'
  tag fix_id: 'F-76325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
