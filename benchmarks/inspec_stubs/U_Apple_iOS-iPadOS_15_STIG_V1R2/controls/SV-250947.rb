control 'SV-250947' do
  title 'Apple iOS/iPadOS 15 must require a valid password be successfully entered before the mobile device data is unencrypted.'
  desc 'Passwords provide a form of access control that prevents unauthorized individuals from accessing computing resources and sensitive data. Passwords may also be a source of entropy for generation of key encryption or data encryption keys. If a password is not required to access data, this data is accessible to any adversary who obtains physical possession of the device. Requiring that a password be successfully entered before the mobile device data is unencrypted mitigates this risk.

Note: MDF PP v2.0 requires a Password Authentication Factor and requires management of its length and complexity. It leaves open whether the existence of a password is subject to management. This requirement addresses the configuration to require a password, which is critical to the cybersecurity posture of the device.

SFR ID: FIA_UAU_EXT.1.1'
  desc 'check', 'Review configuration settings to confirm the device is set to require a passcode before use.

This procedure is performed on the iOS and iPadOS device.

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify "Passcode required" is set to "Yes".

If "Passcode required" is not set to "Yes", this is a finding.'
  desc 'fix', 'Install a configuration profile to require a password to unlock the device.'
  impact 0.7
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54382r801930_chk'
  tag severity: 'high'
  tag gid: 'V-250947'
  tag rid: 'SV-250947r801932_rule'
  tag stig_id: 'AIOS-15-010400'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54336r801931_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
