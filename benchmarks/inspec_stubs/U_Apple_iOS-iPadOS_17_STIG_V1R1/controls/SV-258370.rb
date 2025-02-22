control 'SV-258370' do
  title 'Apple iOS must implement the management setting: not allow a user to remove Apple iOS configuration profiles that enforce DOD security requirements.'
  desc 'Configuration profiles define security policies on Apple iOS devices. If a user is able to remove a configuration profile, the user can then change the configuration that had been enforced by that policy. Relaxing security policies may introduce vulnerabilities the profiles had mitigated. Configuring a profile to never be removed mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review configuration settings to confirm configuration profiles are not removable.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. The procedures below assume the site is not enrolled in Apple's Automatic Device Enrollment and are not applicable to devices under MDM management.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Security" is set to "Never" and "Automatically Remove Profile" is set to "Never".

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management". 
4. Tap each Configuration Profile from the Apple iOS management tool that contains the restrictions for the device.
5. Verify the "Remove Profile" button is not present.

If on the Apple iOS management tool or the iOS device the "Remove Profile" button is available on the configuration profile, this is a finding.)
  desc 'fix', 'Configure the Apple iOS configuration profile so that it can never be removed.

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

When using Apple Configurator, under "General Security", configure "Security" to "Never" and "Automatically Remove Profile" to "Never".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62111r927791_chk'
  tag severity: 'medium'
  tag gid: 'V-258370'
  tag rid: 'SV-258370r927793_rule'
  tag stig_id: 'AIOS-17-013500'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62035r927792_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
