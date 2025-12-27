control 'SV-109025' do
  title 'Samsung Android must be configured to not allow more than 10 consecutive failed authentication attempts.'
  desc 'The more attempts an adversary has to guess a password, the more likely the adversary will enter the correct password and gain access to resources on the device. Setting a limit on the number of attempts mitigates this risk. Setting the limit at 10 or less gives authorized users the ability to make a few mistakes when entering the password but still provides adequate protection against dictionary or brute force attacks on the password.

SFR ID: FMT_SMF_EXT.1.1 #2c, FIA_AFL_EXT.1.5'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device has the maximum number of consecutive failed authentication attempts set at 10 or less. 

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device password requirements section, verify the "max password failures for local wipe" is set to "10" attempts or less.

On the Samsung Android device, do the following:
1. Open Settings >> Biometrics and security >> Other security settings >> Managed device info.
2. Verify "Failed password attempts before deleting all device data" is set to "10" attempts or less.

If on the management tool the "max password failures for local wipe" is not set to "10" attempts or less, or on the Samsung Android device the "Failed password attempts before deleting all device data" is not set to "10" attempts or less, this is a finding.'
  desc 'fix', 'Configure Samsung Android to allow only 10 or fewer consecutive failed authentication attempts.

On the management tool, in the device password requirements section, set the "max password failures for local wipe" to "10" attempts or less.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3.x'
  tag check_id: 'C-98771r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99921'
  tag rid: 'SV-109025r1_rule'
  tag stig_id: 'KNOX-10-000500'
  tag gtitle: 'PP-MDF-301050'
  tag fix_id: 'F-105605r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
