control 'SV-237256' do
  title 'Apple iOS must require a valid password be successfully entered before the mobile device data is unencrypted.'
  desc 'Passwords provide a form of access control that prevents unauthorized individuals from accessing computing resources and sensitive data. Passwords may also be a source of entropy for generation of key encryption or data encryption keys. If a password is not required to access data, this data is accessible to any adversary who obtains physical possession of the device. Requiring that a password be successfully entered before the mobile device data is unencrypted mitigates this risk.

Note: MDF PP v2.0 requires a Password Authentication Factor and requires management of its length and complexity. It leaves open whether the existence of a password is subject to management. This STIGID addresses the configuration to require a password, which is critical to the cybersecurity posture of the device.

SFR ID: FIA_UAU_EXT.1.1'
  desc 'check', 'Review configuration settings to confirm the device is set to require a passcode before use.

This procedure is performed on the iOS device. 

On the Apple iOS device: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6. Verify "Passcode" under PASSWORD POLICY is listed.

If "Passcode" is not listed, this is a finding.'
  desc 'fix', 'Install a configuration profile to require a password to unlock the device.'
  impact 0.7
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-40475r642318_chk'
  tag severity: 'high'
  tag gid: 'V-237256'
  tag rid: 'SV-237256r642320_rule'
  tag stig_id: 'AIOS-12-010500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-40438r642319_fix'
  tag 'documentable'
  tag legacy: ['SV-96521', 'V-81807']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
