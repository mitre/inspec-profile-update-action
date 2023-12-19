control 'SV-84331' do
  title 'Windows 10 Mobile must not display notifications in the Action Center when the device is locked.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #21'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the MOS displays notifications on the lock screen. If feasible, use a spare device and configure it for notifications on common triggers such as calendar appointments. 

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device. It assumes you have an existing device timeout policy in place that will lock the device after a certain period.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "allow Action Center notifications".
3. Verify that setting restriction is turned off/disallowed.

On the Windows 10 Mobile device:

1. If On, tap the power button to turn the screen off otherwise leave the screen off until the timeout period passes. The device could also be powered off instead.
2. Press the power button to turn on the screen.
3. The lock screen background screen should appear. Swipe a finger from the very top of the screen to bring up the action center. 
4. Verify that when the action center appears that that the only thing visible are the 4 configurable settings buttons along with the "all settings" button. 

If an MDM policy for "allow Action Center notifications" is not set to turned off/disallowed or if on the Windows 10 Mobile device any notifications for various services like email show up under the settings buttons, this is a finding.'
  desc 'fix', 'Configure the MDM system to require the "allow Action Center notifications" policy to be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70151r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69709'
  tag rid: 'SV-84331r1_rule'
  tag stig_id: 'MSWM-10-200101'
  tag gtitle: 'PP-MDF-201008'
  tag fix_id: 'F-75913r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000062', 'CCI-000366']
  tag nist: ['AC-14 (1)', 'CM-6 b']
end
