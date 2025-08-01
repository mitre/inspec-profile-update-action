control 'SV-84713' do
  title 'Windows 10 Mobile must lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #02b'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device has the screen lock timeout set to 15 minutes or less. If feasible, use a spare device to determine how much idle time must elapse before the screen lock activates.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to display the device password settings.
2. Verify the device timeout/inactivity setting is turned on.
3. Verify the minimum length is set to 15 minutes.

On the Windows 10 Mobile device:

1. Initiate the test by unlocking the device.
2. Verify that within 15 minutes or less the device screen turns off and if after turning the screen on again that a password is required to gain access to the device.

If the MDM is not configured to require a device lock after 15 minutes or less or; the device fails to lock in 15 minutes or less, this is a finding.'
  desc 'fix', 'Configure Windows 10 Mobile policies to lock the device within 15 minutes or less. 

Deploy the policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70567r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70091'
  tag rid: 'SV-84713r1_rule'
  tag stig_id: 'MSWM-10-201009'
  tag gtitle: 'PP-MDF-201003'
  tag fix_id: 'F-76327r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
