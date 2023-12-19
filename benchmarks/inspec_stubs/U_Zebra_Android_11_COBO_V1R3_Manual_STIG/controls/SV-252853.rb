control 'SV-252853' do
  title 'Zebra Android 11 must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review Zebra Android device configuration settings to determine if the mobile device has the screen lock timeout set to 15 minutes or less.

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM Console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Verify that "Max time to screen lock" is set to any number between 1 and 900. Units are in seconds; therefore, 900 represents 15 minutes.

On the Android 11 device, do the following:
1. Open Settings >> Display.
2. Tap "Screen timeout".
3. Ensure the Screen timeout value is set between 1 and 15 (minutes).

If the EMM console device policy is not set to 15 minutes or less for the screen lock timeout or on the Android 11 device, the device policy is not set to 15 minutes or less for the screen lock timeout, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 11 device to lock the device display after 15 minutes (or less) of inactivity.

On the EMM Console:
1. Open "Lock screen restrictions".
2. Select "Personal Profile".
3. Set "Max time to screen lock" to any number between 1 and 15 (minutes).'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56309r820484_chk'
  tag severity: 'medium'
  tag gid: 'V-252853'
  tag rid: 'SV-252853r820486_rule'
  tag stig_id: 'ZEBR-11-000400'
  tag gtitle: 'PP-MDF-301040'
  tag fix_id: 'F-56259r820485_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
