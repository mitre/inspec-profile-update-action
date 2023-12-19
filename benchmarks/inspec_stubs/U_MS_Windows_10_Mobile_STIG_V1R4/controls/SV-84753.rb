control 'SV-84753' do
  title 'Windows 10 Mobile must be configured to implement the management setting: Require a password be used before unlocking a Windows 10 Mobile device.'
  desc 'Passwords provide a form of access control that prevents unauthorized individuals from accessing computing resources and sensitive data. Passwords may also be a source of entropy for generation of key encryption or data encryption keys. If a password is not required to access data, then this data is accessible to any adversary who obtains physical possession of the device. Requiring that a password be successfully entered before the mobile device data is unencrypted mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #1'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device requires that a password be entered before the device is unlocked. If feasible, use a spare device to test if a password is required to unlock it.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device. 

Check whether the appropriate setting is configured on the MDM.

Administration Console:

1. Ask the MDM administrator to display the "Password" setting in the MDM console.
2. Verify the settings for requiring a password is enforced.

On the Windows 10 Mobile device:

1. Power down the device.
2. Power back up the device.
3. Verify that once the device powers up that the lockscreen is displayed and when you swipe up, the "Enter PIN" screen is shown and a PIN is required to access the device.

If the MDM does not set the policy for requiring a password or if on the phone a password/PIN is not required to access the device, this is a finding.'
  desc 'fix', 'Configure the MDM system to enforce a password is required before unlocking a device. 

Deploy the policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70607r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70131'
  tag rid: 'SV-84753r1_rule'
  tag stig_id: 'MSWM-10-911005'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
