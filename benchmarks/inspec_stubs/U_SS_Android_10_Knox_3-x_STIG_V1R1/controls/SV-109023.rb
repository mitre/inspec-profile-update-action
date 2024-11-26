control 'SV-109023' do
  title 'Samsung Android must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device has the screen lock timeout set to 15 minutes or less.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device password requirements section, verify the "max time to screen lock" is set to "15 minutes" or less.

On the Samsung Android device, do the following:
1. Open Settings >> Display >> Screen timeout.
2. Verify that the listed Screen timeout values are 15 minutes or less.

If on the management tool the "max time to screen lock" is not set to "15 minutes" or less, or on the Samsung Android device the listed Screen timeout values include durations of more than 15 minutes, this is a finding.'
  desc 'fix', 'Configure Samsung Android to lock the device display after 15 minutes (or less) of inactivity.

On the management tool, in the device password requirements section, set the "max time to screen lock" to "15 minutes" or less.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3.x'
  tag check_id: 'C-98769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99919'
  tag rid: 'SV-109023r1_rule'
  tag stig_id: 'KNOX-10-000400'
  tag gtitle: 'PP-MDF-301040'
  tag fix_id: 'F-105603r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
