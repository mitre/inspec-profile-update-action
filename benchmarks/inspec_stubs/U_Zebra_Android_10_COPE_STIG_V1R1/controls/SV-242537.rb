control 'SV-242537' do
  title 'Zebra Android 10 must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or fewer gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set at 10 or fewer. 

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Review the policy configuration that was pushed down to the device and ensure the "Max password failures for local wipe" is set between 1 and 10.

On the Zebra Android 10 device:
1. Open Setting >> Security >> Managed device info. 
2. Verify "Failed password attempts before deleting all device data" is set to 10 or fewer attempts.

If the MDM console device policy is not set to the maximum number of consecutive failed authentication attempts at 10 or fewer, or if on the Zebra Android 10 device, the device policy is not set to the maximum number of consecutive failed authentication attempts at 10 or fewer, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to allow only 10 or fewer consecutive failed authentication attempts.

On the MDM console:
1. Open password requirements.
2. Open device password section.
3. Set "Max password failures for local wipe" to a number between 1 and 10.'
  impact 0.3
  ref 'DPMS Target Zebra Android 10 COPE'
  tag check_id: 'C-45812r714454_chk'
  tag severity: 'low'
  tag gid: 'V-242537'
  tag rid: 'SV-242537r714456_rule'
  tag stig_id: 'ZEBR-10-000500'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-45769r714455_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
